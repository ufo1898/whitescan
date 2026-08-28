#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteScan Web v1.2.0 — 网页版漏洞扫描器
=======================================
标准库 http.server 实现（无 pip 依赖，008 Mac 直接跑）。
复用 whitescan.py 的规则引擎 + GitHub 探测 + AI 深审。

端点:
  GET  /                     前端页面
  POST /api/scan             body: {"target": "owner/repo 或 URL 或 Solidity源码", "ai": bool}
  GET  /api/status           健康+版本（无鉴权，供监控）
  GET  /api/results          最近批量扫描结果
  GET  /api/monitor          链上新合约监控告警（读 monitor_state_*.json / monitor_hits_*.json）

安全:
  - 只监听 127.0.0.1（公网走 nginx 反代 + 随机路径）
  - 仅放行 GitHub 域名的 raw 请求（防 SSRF）
  - body 硬上限 500KB（超限 413），Content-Length 必须声明
  - 并发限制: GitHub 抓取串行（配额保护），AI 复核最多 2 并发
  - 可选 token 鉴权: 设 WHITESCAN_WEB_TOKEN 后 /api/scan 与 /api/results
    需带 X-Token 头或 ?token= 参数（默认关闭，随机路径本身即凭证）
"""
import json
import os
import re
import sys
import threading
import time
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import whitescan as ws  # 复用规则引擎

HOST = os.environ.get("WHITESCAN_WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("WHITESCAN_WEB_PORT", "8710"))
WEB_TOKEN = os.environ.get("WHITESCAN_WEB_TOKEN", "").strip()
MAX_CODE_SIZE = 500_000          # 500KB 上限防内存炸弹
MAX_BODY = MAX_CODE_SIZE + 10_000  # JSON 包装余量

# 允许抓取的域名白名单（SSRF 防护）
ALLOWED_HOSTS = {"raw.githubusercontent.com", "github.com", "api.github.com", "gist.githubusercontent.com"}

_gh_lock = threading.Lock()      # GitHub API 配额保护, 抓取串行
_ai_sem = threading.BoundedSemaphore(2)  # AI 复核并发上限


def looks_like_source(s):
    return "contract " in s or "pragma solidity" in s


def fetch_code_from_input(user_input):
    """把用户输入解析成源码。支持: owner/repo (自动找核心文件) | 完整raw URL | 直接源码"""
    user_input = (user_input or "").strip()
    if not user_input:
        return None, "空输入"
    # 1. 直接贴源码
    if looks_like_source(user_input):
        if len(user_input) > MAX_CODE_SIZE:
            return None, "源码超 500KB"
        return user_input, None
    # 2. raw URL → 校验域名白名单
    if user_input.startswith("http"):
        p = urllib.parse.urlparse(user_input)
        if p.hostname not in ALLOWED_HOSTS:
            return None, f"只允许 GitHub 域名, 拒绝: {p.hostname}"
        try:
            req = urllib.request.Request(user_input, headers={"User-Agent": "whitescan"})
            with ws._opener().open(req, timeout=20) as resp:  # 走代理 opener(008必需)
                code = resp.read(MAX_CODE_SIZE + 1).decode("utf-8", "ignore")
            if len(code) > MAX_CODE_SIZE:
                return None, "URL 内容超 500KB"
            return (code, None) if code else (None, "URL 内容为空")
        except Exception as e:
            return None, f"抓取失败: {str(e)[:100]}"
    # 3. owner/repo → GitHub 找核心借贷文件
    #    注意: 不在此处加锁, gh_lock 的获取/释放统一由 HTTP 层(do_POST)管理,
    #    避免 threading.Lock 非重入导致同线程二次 acquire 自死锁。
    if re.match(r'^[\w.-]+/[\w.-]+$', user_input):
        repo = user_input.strip("/")
        path, code = ws.discover_lending_files(repo)
        if not code:
            return None, f"{repo} 里没找到 CToken/Comptroller 等核心借贷文件"
        return code, None
    return None, "无法识别输入: 给 owner/repo、raw URL 或直接贴 Solidity 源码"


def _check_token(handler):
    """校验 token（配置了才启用）。query 参数优先（方便 curl），其次 X-Token 头"""
    if not WEB_TOKEN:
        return True
    q = urllib.parse.urlparse(handler.path).query
    provided = urllib.parse.parse_qs(q).get("token", [""])[0] or handler.headers.get("X-Token", "")
    return provided == WEB_TOKEN


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WhiteScanWeb"
    # nginx 反代已有随机路径防护, 这里限并发防极端情况
    max_concurrent = threading.BoundedSemaphore(16)

    def log_message(self, fmt, *args):
        pass  # 静默，日志走 stdout 由 systemd 收

    def _send(self, body, status=200, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # 客户端提前断开(如curl超时), 不算错误

    def _json(self, obj, status=200):
        self._send(obj, status)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", ""):
            self._send(PAGE_HTML, ctype="text/html; charset=utf-8")
        elif path == "/api/status":
            self._json({"ok": True, "version": ws.__version__, "rules": len(ws.VULN_RULES),
                        "auth": bool(WEB_TOKEN)})
        elif path == "/api/results":
            if not _check_token(self):
                self._json({"error": "需要 token"}, 401)
                return
            try:
                with open(ws.RESULTS_PATH) as f:
                    self._json(json.load(f))
            except Exception:
                self._json({"results": [], "ts": None})
        elif path == "/api/monitor":
            if not _check_token(self):
                self._json({"error": "需要 token"}, 401)
                return
            self._json(monitor_snapshot())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path != "/api/scan":
            self._json({"error": "not found"}, 404)
            return
        if not _check_token(self):
            self._json({"error": "需要 token"}, 401)
            return
        # body 大小硬限: 必须声明 Content-Length 且 ≤ MAX_BODY
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json({"error": "缺少 Content-Length"}, 400)
            return
        if length <= 0 or length > MAX_BODY:
            self._json({"error": f"body 大小非法(上限 {MAX_BODY} 字节)"}, 413)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except Exception:
            self._json({"error": "bad json"}, 400)
            return
        user_input = str(payload.get("target", ""))
        want_ai = bool(payload.get("ai", False))

        # 贴码扫描不占 GitHub 配额锁, 只有 repo/URL 抓取需要
        need_gh_lock = not looks_like_source(user_input)
        if need_gh_lock and not _gh_lock.acquire(blocking=False):
            self._json({"error": "有 GitHub 抓取进行中, 稍后再试"}, 429)
            return
        try:
            code, err = fetch_code_from_input(user_input)
            if err:
                self._json({"error": err}, 400)
                return
            hits = ws.scan_code(code)
            result = {
                "input": user_input[:120],
                "source": "pasted" if looks_like_source(user_input) else "github",
                "lines": code.count("\n") + 1,
                "hits": hits,
                "ai": None,
                "ts": ws._now(),
            }
            # AI 深审（可选, 并发上限 2）
            if want_ai and hits:
                if _ai_sem.acquire(blocking=False):
                    try:
                        key = os.environ.get("WHITESCAN_AI_KEY") or ws._load_ai_key()
                        base = os.environ.get("WHITESCAN_AI_BASE", "https://api.b.ai/v1")
                        model = os.environ.get("WHITESCAN_AI_MODEL", "glm-5.3-flash")
                        if key:
                            verdicts = ws.ai_review(code, hits, base, key, model)
                            result["ai"] = {"verdicts": verdicts}
                        else:
                            result["ai"] = {"error": "未配置 AI key"}
                    except Exception as e:
                        result["ai"] = {"error": str(e)[:200]}
                    finally:
                        _ai_sem.release()
                else:
                    result["ai"] = {"error": "AI 复核并发已满(2), 稍后重试或关闭 AI"}
            self._json(result)
        finally:
            if need_gh_lock:
                _gh_lock.release()


PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhiteScan — 智能合约漏洞扫描</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--tx:#e6edf3;--dim:#8b949e;
--red:#f85149;--yel:#d29922;--grn:#3fb950;--blue:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;padding:16px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:20px;margin-bottom:2px}
h1 span{color:var(--blue)}
.sub{color:var(--dim);font-size:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px}
textarea,input[type=text]{width:100%;background:#0d1117;color:var(--tx);border:1px solid var(--border);
border-radius:6px;padding:10px;font:13px/1.5 "SF Mono",Consolas,monospace;resize:vertical}
textarea{height:140px}
input[type=text]{height:40px}
.row{display:flex;gap:10px;margin-top:10px;align-items:center;flex-wrap:wrap}
button{background:var(--blue);color:#fff;border:0;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer;font-weight:600}
button:disabled{opacity:.5;cursor:wait}
label.chk{color:var(--dim);font-size:13px;display:flex;gap:5px;align-items:center;cursor:pointer}
.status{font-size:12px;color:var(--dim)}
.ex{color:var(--dim);font-size:12px;margin-top:8px}
.ex code{color:var(--blue);cursor:pointer}
.summary{display:flex;gap:14px;margin-bottom:12px;font-size:13px}
.summary b{font-size:18px}
.hit{border:1px solid var(--border);border-left:3px solid var(--dim);border-radius:6px;padding:10px 12px;margin-bottom:8px;background:#0d1117}
.hit.HIGH{border-left-color:var(--red)}
.hit.MED{border-left-color:var(--yel)}
.hit.LOW{border-left-color:var(--grn)}
.hit .head{display:flex;justify-content:space-between;gap:8px;align-items:baseline;flex-wrap:wrap}
.hit .rid{font-family:"SF Mono",Consolas,monospace;font-size:13px;font-weight:700}
.hit .sev{font-size:11px;padding:1px 8px;border-radius:10px;font-weight:600}
.sev.HIGH{background:rgba(248,81,73,.15);color:var(--red)}
.sev.MED{background:rgba(210,153,34,.15);color:var(--yel)}
.sev.LOW{background:rgba(63,185,80,.15);color:var(--grn)}
.hit .why{color:var(--dim);font-size:13px;margin-top:4px}
.ai-box{margin-top:8px;padding-top:8px;border-top:1px dashed var(--border);font-size:13px}
.ai-box .tp{color:var(--red)}
.ai-box .fp{color:var(--grn)}
.ai-box .un{color:var(--yel)}
.err{color:var(--red);font-size:13px;padding:10px}
.loading{color:var(--blue);font-size:13px;padding:10px}
.ok{color:var(--grn)}
#tokenRow{display:none}
@media(max-width:600px){.summary{flex-wrap:wrap}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ WhiteScan <span id="ver"></span></h1>
  <div class="sub" id="rulecount">智能合约漏洞扫描 — 规则+AI 语义复核</div>

  <div class="card">
    <div class="row" id="tokenRow"><input type="text" id="token" placeholder="访问 Token" style="height:36px"></div>
    <input type="text" id="target" placeholder="owner/repo（如 lend-fam/compound-fork）或 raw.githubusercontent.com 链接" spellcheck="false" style="margin-top:0">
    <textarea id="code" placeholder="…或直接粘贴 Solidity 源码"></textarea>
    <div class="row">
      <button id="scanBtn" onclick="doScan()">扫描</button>
      <label class="chk"><input type="checkbox" id="ai" checked> AI 复核（慢，~60s）</label>
      <span class="status" id="status"></span>
    </div>
    <div class="ex">输入任一即可。示例:
      <code onclick="document.getElementById('target').value=this.textContent">lend-fam/compound-fork</code>
    </div>
  </div>

  <div id="results"></div>

  <div class="card" id="monCard" style="display:none">
    <h2 style="margin:0 0 8px">📡 链上新合约实时监控</h2>
    <div id="monBody" style="font-size:13px">加载中…</div>
  </div>
</div>
<script>
function tok(){const t=document.getElementById('token').value.trim();return t}
function hdrs(){const h={'Content-Type':'application/json'};const t=tok();if(t)h['X-Token']=t;return h}
async function doScan(){
  const btn=document.getElementById('scanBtn'),st=document.getElementById('status');
  const target=document.getElementById('target').value.trim();
  const code=document.getElementById('code').value.trim();
  if(!target&&!code){st.textContent='填 repo 或贴源码';return}
  btn.disabled=true;st.textContent='扫描中…';
  document.getElementById('results').innerHTML='<div class="loading">⏳ 规则扫描…'+(document.getElementById('ai').checked?' AI 复核约需 60s…':'')+'</div>';
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:hdrs(),
      body:JSON.stringify({target:target||code,ai:document.getElementById('ai').checked})});
    if(r.status===401){document.getElementById('tokenRow').style.display='flex';
      document.getElementById('results').innerHTML='<div class="err">🔒 需要 Token（输入后重扫，自动记住）</div>';st.textContent='';btn.disabled=false;return}
    const d=await r.json();
    if(d.error){document.getElementById('results').innerHTML='<div class="err">❌ '+d.error+'</div>';st.textContent='';}
    else{render(d);st.textContent='完成 '+d.ts;if(tok())localStorage.setItem('ws_tok',tok());}
  }catch(e){document.getElementById('results').innerHTML='<div class="err">请求失败: '+e+'</div>';}
  btn.disabled=false;
}
function esc(s){return (s||'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}
function render(d){
  const el=document.getElementById('results');
  const high=d.hits.filter(h=>h.sev==='HIGH').length, med=d.hits.filter(h=>h.sev==='MED').length;
  let html=`<div class="card">
    <div class="summary">
      <span>命中 <b>${d.hits.length}</b></span>
      <span style="color:var(--red)">高危 <b>${high}</b></span>
      <span style="color:var(--yel)">中危 <b>${med}</b></span>
      <span class="status">${esc(d.source)} · ${d.lines} 行 · ${esc(d.ts)}</span>
    </div>`;
  if(!d.hits.length) html+='<div class="ok">✅ 规则无命中（不代表无漏洞，AI 复核可见细节）</div>';
  for(const h of d.hits){
    html+=`<div class="hit ${h.sev}">
      <div class="head"><span class="rid">${esc(h.id)}</span><span class="sev ${h.sev}">${h.sev}</span></div>
      <div>${esc(h.desc)}</div>
      <div class="why">${esc(h.why)}</div>`;
    if(d.ai&&d.ai.verdicts!==undefined){
      const v=(d.ai.verdicts||[]).find(v=>v.id===h.id);
      if(v){
        const cls={true_positive:'tp',false_positive:'fp',uncertain:'un'}[v.verdict]||'un';
        const mark={true_positive:'🔴 真漏洞',false_positive:'🟢 误报',uncertain:'🟡 存疑'}[v.verdict]||v.verdict;
        html+=`<div class="ai-box"><span class="${cls}">${mark}</span> 置信${v.confidence??'?'} — ${esc(v.reason)}</div>`;
      }
    } else if(d.ai&&d.ai.error){
      html+=`<div class="ai-box">⚠️ AI 复核失败: ${esc(d.ai.error)}</div>`;
    }
    html+='</div>';
  }
  html+='</div>';
  el.innerHTML=html;
}
function renderMon(d){
  const el=document.getElementById('monBody');
  if(!d.chains||!d.chains.length){el.innerHTML='<span style="color:var(--dim)">监控未运行（whitescan-monitor 服务未启动或尚无数据）</span>';return}
  let html='';
  for(const c of d.chains){
    const st=c.state||{};
    const last=st.last_height?('#'+st.last_height):'?';
    const ago=st.ts?Math.floor((Date.now()/1000-st.ts)/60):'?';
    const hits=c.hits||[];
    html+=`<div style="margin-bottom:10px">
      <div><b>${esc(c.chain)}</b> · 扫至块${esc(last)} · 状态更新于 ${ago} 分钟前 · 告警 <b style="color:${hits.length?'var(--red)':'var(--grn)'}">${hits.length}</b></div>`;
    for(const h of hits.slice().reverse()){
      const sevCls=h.hits&&h.hits.some(x=>x.sev==='HIGH')?'HIGH':(h.hits&&h.hits.some(x=>x.sev==='MED')?'MED':'LOW');
      html+=`<div class="hit ${sevCls}" style="margin-top:6px">
        <div class="head"><span class="rid">${esc(h.contract_name||'')}</span><span class="sev ${sevCls}">${sevCls}</span></div>
        <div style="font-size:12px">${esc(h.address)} @ 块${h.block} · ${new Date(h.ts*1000).toLocaleString()}</div>
        ${(h.hits||[]).map(x=>`<div>[${x.sev}] ${esc(x.id)}: ${esc((x.desc||'').slice(0,70))}</div>`).join('')}
        <div class="why"><a href="${esc(h.explorer_ui)}/address/${esc(h.address)}" target="_blank" style="color:var(--blue)">查看合约 ↗</a> · 创建tx ${esc((h.tx||'').slice(0,18))}…</div>
      </div>`;
    }
    html+='</div>';
  }
  el.innerHTML=html;
}
fetch('/api/status').then(r=>r.json()).then(d=>{
  document.getElementById('ver').textContent='v'+d.version;
  document.getElementById('rulecount').textContent=d.rules+' 条规则 + AI 语义复核'+(d.auth?' · 🔒token模式':'');
  if(d.auth){document.getElementById('tokenRow').style.display='flex';
    const saved=localStorage.getItem('ws_tok');if(saved)document.getElementById('token').value=saved;}
  document.getElementById('monCard').style.display='block';
  const loadMon=()=>fetch('/api/monitor').then(r=>r.json()).then(renderMon).catch(()=>{});
  loadMon(); setInterval(loadMon, 30000);
});
</script>
</body>
</html>"""


def monitor_snapshot():
    """聚合各链监控状态与告警（monitor 进程落盘，web 只读）"""
    here = os.path.dirname(os.path.abspath(__file__))
    chains = []
    try:
        for f in sorted(os.listdir(here)):
            m = re.match(r"monitor_state_(\w+)\.json$", f)
            if not m:
                continue
            ck = m.group(1)
            state = {}
            try:
                with open(os.path.join(here, f)) as fh:
                    state = json.load(fh)
            except Exception:
                pass
            hits = []
            hp = os.path.join(here, f"monitor_hits_{ck}.json")
            try:
                with open(hp) as fh:
                    hits = json.load(fh)[-30:]  # 最近的
            except Exception:
                pass
            chains.append({"chain": ck, "state": state, "hits": hits})
    except Exception:
        pass
    return {"ok": True, "chains": chains, "ts": int(time.time())}


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"WhiteScan Web v{ws.__version__} listening on http://{HOST}:{PORT} "
          f"(rules={len(ws.VULN_RULES)}, auth={'on' if WEB_TOKEN else 'off'})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
