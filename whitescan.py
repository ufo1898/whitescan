#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteScan v1.0.0 — 冷门 fork 协议批量漏洞扫描器
================================================
把「老刘白帽审计方法论」做成程序：GitHub 批量找冷门 Compound/Aave fork
→ 正则特征初筛 → AI 语义深审（过滤误报）→ Markdown 报告。

用法:
  whitescan scan [--source github|dir] [--target DIR] [--limit N] [--ai] [--no-ai]
  whitescan ai <scan_results.json> [--max N]
  whitescan report <scan_results.json> [-o OUT.md]
  whitescan doctor          自检：token/网络/AI 依赖
  whitescan update          自更新（GitHub Release / raw fallback）

架构: 单文件标准库实现（macOS 系统无 pip 也能跑），模块化函数便于热更新。
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error


def _opener():
    """带可选代理的 opener（WHITESCAN_PROXY 环境变量，如 http://127.0.0.1:10900）"""
    proxy = os.environ.get("WHITESCAN_PROXY", "").strip()
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    # 无代理时不继承系统环境代理，行为可预测
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))

from datetime import datetime, timezone

__version__ = "1.1.1"
VERSION_URL = "https://raw.githubusercontent.com/ufo1898/whitescan/main/VERSION"
SELF_URL = "https://raw.githubusercontent.com/ufo1898/whitescan/main/whitescan.py"
REPORT_DIR = os.path.expanduser("~/whitescan/reports")
RESULTS_PATH = os.path.expanduser("~/whitescan/scan_results.json")
TOKEN_PATH = os.path.expanduser("~/whitescan/github_token.txt")
AI_TIMEOUT = 120  # 秒

# ============================================================
# 漏洞规则库 v3（14 种，每种含: id/描述/严重级/检测函数）
# ============================================================

def detect_first_depositor(code):
    """第一笔存款攻击: exchangeRate 在 supply==0 时返回 initial 值且无首笔锁仓"""
    if not (re.search(r'_totalSupply\s*==\s*0|totalSupply\s*==\s*0', code)
            and re.search(r'initialExchangeRate', code)):
        return None
    has_lock = re.search(r'accountTokens\[address\(0\)\]|totalSupply\s*=\s*[1-9]\d*', code)
    return None if has_lock else "exchangeRate 存在 supply==0 分支且无首笔锁仓，首存者可捐币拉高汇率抽取后入者本金"

def detect_oracle_spot_price(code):
    has_reserves = re.search(r'getReserves\(\)', code)
    has_safe = re.search(r'twap|TWAP|timeWeighted|observe|deviation|chainlink|Chainlink|pyth|Pyth', code)
    if has_reserves and not has_safe:
        return "AMM getReserves 直接当价格，可闪电贷操纵"
    return None

def detect_reentrancy(code):
    has_call = re.search(r'\.call\{value:|\.call\(|\.send\(|\.delegatecall\(', code)
    has_guard = re.search(r'nonReentrant|ReentrancyGuard|_notEntered|_status\s*=', code)
    if has_call and not has_guard:
        return "存在低级外部调用且无重入保护"
    return None

def detect_tx_origin(code):
    if re.search(r'tx\.origin', code):
        return "使用 tx.origin 鉴权，可被钓鱼合约绕过"
    return None

def detect_selfdestruct(code):
    if re.search(r'selfdestruct\s*\(', code) and not re.search(
            r'onlyOwner|require\(msg\.sender\s*==\s*owner|hasRole', code):
        return "selfdestruct 无权限保护，任何人可销毁合约"
    return None

def detect_unchecked_call(code):
    if re.search(r'\.call\(', code) and not re.search(
            r'require\([^)]*success|require\([^)]*ok\b|if\s*\(!\s*success|if\s*\(!\s*ok', code):
        return "低级 .call 返回值未检查，失败被静默吞掉"
    return None

def detect_arbitrary_delegatecall(code):
    if re.search(r'\.delegatecall\s*\(\s*abi\.encode|\.delegatecall\(_', code):
        return "delegatecall 目标来自参数/变量，可被指向恶意实现"
    return None

def detect_integer_overflow(code):
    if re.search(r'pragma\s+solidity\s+[\^~]?0\.[0-7]', code) and not re.search(
            r'SafeMath|safemath|unchecked\s*\{', code):
        return "pragma <0.8 且无 SafeMath，算术运算可溢出"
    return None

def detect_zero_check(code):
    if re.search(r'constructor\([^)]*address|function\s+\w*[Ss]et\w*\([^)]*address', code) and not re.search(
            r'address\(0\)', code):
        return "地址参数无零地址校验，可误配成黑洞"
    return None

def detect_unprotected_mint(code):
    if re.search(r'function\s+mint\s*\(', code) and not re.search(
            r'onlyOwner|require\(msg\.sender\s*==\s*owner|hasRole|onlyRole|_mint\s*\(', code):
        return "mint 无权限控制，任何人可增发"
    return None

def detect_block_timestamp(code):
    if not re.search(r'block\.timestamp', code):
        return None
    pure_staleness = (re.search(r'block\.timestamp\s*-\s*\w+\s*[<>]=?\s*\w+', code)
                      and not re.search(r'block\.timestamp\s*[*/+]|keccak256\([^)]*block\.timestamp', code))
    return None if pure_staleness else "block.timestamp 参与关键逻辑，矿工可小幅操纵"

def detect_unchecked_transfer(code):
    if re.search(r'\.transfer\(|\.send\(', code) and not re.search(
            r'require\([^)]*\.transfer|require\([^)]*\.send|if\s*\([^)]*\.transfer|if\s*\([^)]*\.send', code):
        return ".transfer/.send 返回值未检查"
    return None

def detect_unprotected_initializer(code):
    if re.search(r'function\s+(initialize|init)\s*\(', code) and not re.search(
            r'initializer\b|onlyOwner|onlyRole|require\(msg\.sender\s*==|_initialized|_initializing', code):
        return "initialize 无 initializer/权限保护，可被重新初始化接管"
    return None

def detect_proxy_storage_collision(code):
    if re.search(r'\.delegatecall\(', code) and re.search(r'function\s+initialize\s*\(', code):
        return "delegatecall 与 initialize 共存，init 写 slot 可能污染 proxy 存储"
    return None

def detect_erc4626_inflation(code):
    """ERC-4626 通胀攻击(2023-25高发): shares=assets*totalSupply/totalAssets 且无虚拟份额偏移"""
    if not re.search(r'4626|convertToShares|previewDeposit|previewMint|_convertToShares', code, re.I):
        return None
    has_virtual = re.search(r'DECIMAL_OFFSET|1e\d+\s*\*\s*10\s*\*\*|virtualShares|\+\s*10\s*\*\*\s*\d+', code)
    ratio = re.search(r'totalSupply\s*\*\s*assets|assets\s*\*\s*totalSupply|\*\s*totalAssets\(\)|/\s*totalAssets\(\)', code)
    if ratio and not has_virtual:
        return "ERC-4626 份额=assets*totalSupply/totalAssets 无虚拟份额偏移，首存者捐1wei可通胀抽取后入者"
    return None

def detect_signature_replay(code):
    """签名重放(2024高发: Penpie/Uniswap v3 LP): ecrecover 缺 nonce/deadline/chainId"""
    if not re.search(r'ecrecover\s*\(', code):
        return None
    has_nonce = re.search(r'nonce|usedSignatures|used\s*\[|signatures\s*\[|_hashes\s*\[|consumed', code)
    has_deadline = re.search(r'deadline|expiry|expiration|validUntil', code)
    has_chainid = re.search(r'block\.chainid|chainId|CHAIN_ID', code)
    missing = [n for n, ok in (("nonce", has_nonce), ("deadline", has_deadline), ("chainId", has_chainid)) if not ok]
    if missing:
        return f"ecrecover 验签缺 {'/'.join(missing)} 保护，签名可被截获重放"
    return None

def detect_unprotected_callback(code):
    """回调未验证调用方(2024高发: UniswapV3SwapCallback/onFlashLoan 仿冒)"""
    for cb in ("uniswapV3SwapCallback", "uniswapV2Call", "pancakeCall", "onFlashLoan",
               "executeOperation", "uniswapV3FlashCallback", "dodoFlashLoan", "gmxOrderCallback"):
        m = re.search(r'function\s+' + cb + r'\s*\([^)]*\)[^{;]*\{', code)
        if m:
            seg = code[m.end():m.end()+800]
            # 从函数体开始检查(排除签名参数名干扰), 必须有真实的 == 验证
            if not re.search(r'msg\.sender\s*==|initiator\s*==|_verify\s*\(|factory\s*\(\)|_isTrusted|trustedSender', seg):
                return f"回调 {cb} 未验证 msg.sender 合法性，任何人可伪造调用盗取授权资产"
    return None

def detect_weak_randomness(code):
    if not re.search(r'random|Random|lottery|raffle|seed', code):
        return None
    if re.search(r'keccak256\s*\([^)]*(block\.(timestamp|difficulty|number)|msg\.sender)|blockhash\s*\(|block\.prevrandao', code):
        return "随机数来自 block.timestamp/difficulty/prevrandao，矿工与提前计算者可操纵"
    return None

def detect_unbounded_loop_dos(code):
    """无上限数组循环(2024常见DoS: 数组被外部注入撑爆 gas)"""
    for m in re.finditer(r'for\s*\(\s*uint\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length', code):
        arr = m.group(1)
        seg = code[max(0, m.start()-300):m.start()]
        if not re.search(r'\b' + arr + r'\.push\s*\(', seg) and not re.search(r'max\w*Length|cap|MAX_', code):
            return f"for 循环遍历数组 {arr} 无长度上限，数组膨胀可 DoS 关键函数"
    return None

def detect_missing_swap_deadline(code):
    """swap 无 deadline 参数(三明治滞留单)"""
    has_swap = re.search(r'swapExactTokensFor|swapTokensForExact|exactInputSingle|exactInput\(|makeOrder|placeOrder', code)
    if has_swap and not re.search(r'deadline|block\.timestamp\s*\+\s*|expiry', code):
        return "交易函数无 deadline 检查，滞留单可被三明治套利"
    return None


# (规则id, 中文名, 严重级, 检测函数)
VULN_RULES = [
    ("COMPOUND-V2-FIRST-DEPOSITOR", "第一笔存款攻击(抽干后入者)", "HIGH",   detect_first_depositor),
    ("ORACLE-SPOT-PRICE",           "预言机spot价格操纵",       "HIGH",   detect_oracle_spot_price),
    ("UNPROTECTED-INITIALIZER",     "未保护initialize",         "HIGH",   detect_unprotected_initializer),
    ("ARBITRARY-DELEGATECALL",      "任意delegatecall",         "HIGH",   detect_arbitrary_delegatecall),
    ("UNPROTECTED-MINT",            "未保护mint(无限增发)",     "HIGH",   detect_unprotected_mint),
    ("REENTRANCY",                  "重入攻击",                 "MED",    detect_reentrancy),
    ("SELFDESTRUCT",                "未保护selfdestruct",       "MED",    detect_selfdestruct),
    ("UNCHECKED-CALL",              "未检查call返回值",         "MED",    detect_unchecked_call),
    ("INTEGER-OVERFLOW",            "整数溢出(<0.8无SafeMath)", "MED",    detect_integer_overflow),
    ("PROXY-STORAGE-COLLISION",     "代理存储冲突",             "MED",    detect_proxy_storage_collision),
    ("TX-ORIGIN",                   "tx.origin鉴权",            "LOW",    detect_tx_origin),
    ("MISSING-ZERO-CHECK",          "缺零地址检查",             "LOW",    detect_zero_check),
    ("BLOCK-TIMESTAMP",             "时间戳依赖",               "LOW",    detect_block_timestamp),
    ("UNCHECKED-TRANSFER",          "未检查transfer返回值",     "LOW",    detect_unchecked_transfer),
    ("ERC4626-INFLATION",           "ERC-4626通胀攻击",         "HIGH",   detect_erc4626_inflation),
    ("SIGNATURE-REPLAY",            "签名重放(缺nonce/deadline/chainId)", "HIGH", detect_signature_replay),
    ("UNPROTECTED-CALLBACK",        "回调未验证调用方",         "HIGH",   detect_unprotected_callback),
    ("WEAK-RANDOMNESS",             "弱随机数",                 "MED",    detect_weak_randomness),
    ("UNBOUNDED-LOOP-DOS",          "无上限循环DoS",            "MED",    detect_unbounded_loop_dos),
    ("MISSING-SWAP-DEADLINE",       "swap无deadline",           "LOW",    detect_missing_swap_deadline),
]

HIGH_RULE_IDS = {r[0] for r in VULN_RULES if r[2] == "HIGH"}

# 借贷协议核心文件路径（按优先级）
TOKEN_PATHS = [
    "contracts/CToken.sol", "src/CToken.sol",
    "contracts/CErc20.sol", "src/CErc20.sol",
    "contracts/CEther.sol", "src/CEther.sol",
    "contracts/Comptroller.sol", "src/Comptroller.sol",
    "contracts/LendingPool.sol", "src/LendingPool.sol",
    "contracts/Controller.sol", "src/Controller.sol",
]

# ============================================================
# GitHub 探测层
# ============================================================

def load_token():
    for p in (TOKEN_PATH, "/root/audit/github_token.txt"):
        try:
            with open(p) as f:
                t = f.read().strip()
                if t:
                    return t
        except OSError:
            continue
    return None

def _headers():
    h = {"User-Agent": "whitescan", "Accept": "application/vnd.github+json"}
    token = load_token()
    if token:
        h["Authorization"] = f"token {token}"
    return h

def gh_search(query, per_page=30):
    url = ("https://api.github.com/search/repositories?q="
           + urllib.parse.quote(query) + "&sort=stars&order=asc&per_page=%d" % per_page)
    req = urllib.request.Request(url, headers=_headers())
    with _opener().open(req, timeout=25) as resp:
        return json.loads(resp.read())

def gh_file_raw(repo, path):
    """优先 raw 直取（省 API 配额），失败走 contents API（base64）"""
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "whitescan"})
            with _opener().open(req, timeout=15) as resp:
                return resp.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue
    # contents API fallback
    try:
        url = f"https://api.github.com/repos/{repo}/contents/{path}"
        req = urllib.request.Request(url, headers=_headers())
        with _opener().open(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return base64.b64decode(data.get("content", "")).decode("utf-8", "ignore")
    except Exception:
        return None

def gh_repo_root_listing(repo):
    """列 repo 根目录文件，找实际的 CToken/Comptroller 文件名"""
    try:
        url = f"https://api.github.com/repos/{repo}/contents/"
        req = urllib.request.Request(url, headers=_headers())
        with _opener().open(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return [item["path"] for item in data if item.get("type") == "file"]
    except Exception:
        return []

def discover_lending_files(repo):
    """优先猜常见路径，猜不中就列根目录模糊匹配借贷协议文件"""
    for path in TOKEN_PATHS:
        code = gh_file_raw(repo, path)
        if code:
            return path, code
    # 模糊匹配：根目录里的 .sol 文件，名字像核心合约
    listing = gh_repo_root_listing(repo)
    keywords = ("CToken", "Comptroller", "Lending", "Lend", "Market", "Pool",
                "Controller", "Bank", "Vault", "Borrow")
    for item in listing:
        if item.endswith(".sol") and any(k.lower() in item.lower() for k in keywords):
            code = gh_file_raw(repo, item)
            if code:
                return item, code
    return None, None

# ============================================================
# 扫描引擎
# ============================================================

def scan_code(code):
    """对单份源码跑全部规则，返回 hits 列表"""
    hits = []
    for rid, desc, sev, fn in VULN_RULES:
        try:
            why = fn(code)
        except Exception:
            continue
        if why:
            hits.append({"id": rid, "desc": desc, "sev": sev, "why": why})
    return hits

def scan_repo(repo):
    path, code = discover_lending_files(repo)
    if not code:
        return None, []
    return path, scan_code(code)

def search_queries():
    return [
        "compound fork solidity language:Solidity",
        "compound v2 fork language:Solidity",
        "aave fork solidity language:Solidity",
        "aave v2 fork language:Solidity",
        "lending protocol fork solidity language:Solidity",
        "defi lending borrow solidity fork",
    ]

def cmd_scan(args):
    """主扫描流程: GitHub 搜索 → 逐 repo 初筛 → 结果落盘"""
    source = getattr(args, "source", "github")
    target = getattr(args, "target", None)
    limit = getattr(args, "limit", 50)
    repos = []  # (repo, stars)

    if source == "dir":
        if not target or not os.path.isdir(target):
            print(json.dumps({"error": f"目录不存在: {target}"}, ensure_ascii=False))
            return 2
        for fn in sorted(os.listdir(target)):
            if fn.endswith(".sol"):
                p = os.path.join(target, fn)
                try:
                    code = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                hits = scan_code(code)
                if hits:
                    print(f"🔴 {fn}")
                    for h in hits:
                        print(f"   └─ [{h['sev']}] {h['id']}: {h['desc']}")
                    repos.append((fn, 0, p, hits))
        out = [{"repo": r[0], "stars": 0, "file": r[2], "hits": r[3]} for r in repos]
        _save_results(out)
        return 0

    queries = search_queries()
    seen = set()
    print(f"=== WhiteScan v{__version__} GitHub 批量扫描（规则 {len(VULN_RULES)} 条）===", flush=True)
    for q in queries:
        try:
            r = gh_search(q, per_page=min(limit, 50))
            for item in r.get("items", []):
                repo = item["full_name"]
                if repo in seen:
                    continue
                seen.add(repo)
                stars = item.get("stargazers_count", 0)
                updated = item.get("updated_at", "")
                path, hits = scan_repo(repo)
                if hits:
                    high = sum(1 for h in hits if h["sev"] == "HIGH")
                    tag = "🔴" if high else "🟡"
                    print(f"{tag} {repo} (⭐{stars}) [{path}]", flush=True)
                    for h in hits:
                        print(f"   └─ [{h['sev']}] {h['id']}: {h['desc']}", flush=True)
                    repos.append((repo, stars, path, hits))
                    # 增量落盘：进程被杀也不丢结果
                    _save_results([{"repo": x[0], "stars": x[1], "file": x[2], "hits": x[3]} for x in repos])
        except Exception as e:
            msg = str(e)
            print(f"  [搜索 '{q}' 失败: {msg[:80]}]", flush=True)
        time.sleep(1.2)  # 搜索 API 配额保护

    out = [{"repo": r[0], "stars": r[1], "file": r[2], "hits": r[3]} for r in repos]
    _save_results(out)
    print(f"\n=== 完成: 扫 {len(seen)} repo, 命中 {len(out)} (落盘 {RESULTS_PATH}) ===", flush=True)
    return 0

def _save_results(records):
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"version": __version__, "ts": _now(), "results": records}, f, indent=2, ensure_ascii=False)

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ============================================================
# AI 语义深审层（b.ai 免费 glm-5.3）
# ============================================================

def ai_review(code, hits, base_url, api_key, model):
    """调 OpenAI 兼容 API 让大模型复核命中，返回 verdict 列表"""
    system = (
        "你是资深智能合约安全审计员。用户给出 Solidity 合约源码和静态扫描的命中列表。"
        "请逐条判定每个命中是真漏洞还是误报，重点看：权限控制、资金路径、修复特征。"
        "严格输出 JSON: {\"verdicts\":[{\"id\":\"规则id\",\"verdict\":\"true_positive|false_positive|uncertain\",\"confidence\":0到1,\"reason\":\"一句话中文\"}]}"
    )
    user = f"## 命中列表\n{json.dumps(hits, ensure_ascii=False)}\n\n## 合约源码\n```solidity\n{code[:40000]}\n```"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "max_tokens": 16000,
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    with _opener().open(req, timeout=AI_TIMEOUT) as resp:
        data = json.loads(resp.read())
    content = data["choices"][0]["message"].get("content") or ""
    if not content.strip():
        raise ValueError("AI 输出为空(推理耗尽输出预算)，加大 max_tokens 或换模型")
    # glm 推理模型可能带 ```json 包裹，剥掉
    m = re.search(r'\{[\s\S]*\}', content)
    if not m:
        raise ValueError(f"AI 返回无 JSON: {content[:200]}")
    parsed = json.loads(m.group(0))
    return parsed.get("verdicts", [])

def cmd_ai(args):
    """对 scan 结果做 AI 复核，只审 HIGH 或 --all"""
    path = args.scan_file
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    records = data.get("results", data) if isinstance(data, dict) else data

    base_url = os.environ.get("WHITESCAN_AI_BASE", "https://api.b.ai/v1")
    api_key = os.environ.get("WHITESCAN_AI_KEY") or _load_ai_key()
    model = os.environ.get("WHITESCAN_AI_MODEL", "glm-5.3-flash")
    if not api_key:
        print(json.dumps({"error": "缺 AI key: 设 WHITESCAN_AI_KEY 或 ~/whitescan/ai_key.txt"}, ensure_ascii=False))
        return 2

    max_n = getattr(args, "max", 10) or 10
    reviewed = 0
    for rec in records[:max_n]:
        code = None
        file_path = rec.get("file") or ""
        if file_path.startswith("/"):
            try:
                code = open(file_path, encoding="utf-8", errors="ignore").read()
            except OSError:
                pass
        elif file_path:
            code = gh_file_raw(rec["repo"], file_path)
        if not code:
            rec["ai"] = {"error": "源码获取失败"}
            continue
        hits = rec.get("hits", [])
        try:
            verdicts = ai_review(code, hits, base_url, api_key, model)
            rec["ai"] = {"verdicts": verdicts, "model": model, "ts": _now()}
            tp = [v for v in verdicts if v.get("verdict") == "true_positive"]
            fp = [v for v in verdicts if v.get("verdict") == "false_positive"]
            print(f"🤖 {rec['repo']}: {len(tp)} 真漏洞, {len(fp)} 误报", flush=True)
            for v in tp:
                print(f"   ✅ [{v.get('confidence','?')}] {v['id']}: {v.get('reason','')[:80]}", flush=True)
        except Exception as e:
            rec["ai"] = {"error": str(e)[:200]}
            print(f"   ⚠️ {rec['repo']}: AI 审核失败 {str(e)[:80]}", flush=True)
        reviewed += 1
        # 结果写回
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n=== AI 复核完成 {reviewed} 项, 已写回 {path} ===", flush=True)
    return 0

def _load_ai_key():
    try:
        with open(os.path.expanduser("~/whitescan/ai_key.txt")) as f:
            return f.read().strip()
    except OSError:
        return None

# ============================================================
# 报告层
# ============================================================

def cmd_report(args):
    path = args.scan_file
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    records = data.get("results", data) if isinstance(data, dict) else data
    ts = data.get("ts", _now()) if isinstance(data, dict) else _now()

    lines = [
        f"# WhiteScan 审计报告",
        f"",
        f"- 生成时间: {ts}",
        f"- 扫描器: v{__version__}（{len(VULN_RULES)} 条规则 + AI 复核）",
        f"- 命中项目: {len(records)}",
        f"",
        f"| 项目 | ⭐ | 文件 | 命中 | AI判定 |",
        f"|---|---|---|---|---|",
    ]
    tp_total = 0
    for rec in records:
        hits = rec.get("hits", [])
        ai = rec.get("ai", {})
        ai_summary = "—"
        if "verdicts" in ai:
            tp = [v for v in ai["verdicts"] if v.get("verdict") == "true_positive"]
            tp_total += len(tp)
            ai_summary = f"{len(tp)} 真漏洞" if tp else "均误报"
        elif "error" in ai:
            ai_summary = "审核失败"
        lines.append(f"| {rec['repo']} | {rec.get('stars',0)} | `{rec.get('file','?')}` | "
                     f"{', '.join(h['id'] for h in hits)} | {ai_summary} |")
    lines.append("")
    lines.append("## 详情")
    for rec in records:
        lines.append(f"### {rec['repo']}")
        lines.append(f"- 文件: `{rec.get('file','?')}` (⭐{rec.get('stars',0)})")
        for h in rec.get("hits", []):
            lines.append(f"- **[{h['sev']}] {h['id']}** — {h['desc']}")
            lines.append(f"  - {h.get('why','')}")
        ai = rec.get("ai", {})
        for v in ai.get("verdicts", []):
            mark = {"true_positive": "✅真", "false_positive": "❌误", "uncertain": "❓疑"}.get(
                v.get("verdict"), v.get("verdict"))
            lines.append(f"- AI: {mark} {v['id']} (置信 {v.get('confidence','?')}) — {v.get('reason','')}")
        if "error" in ai:
            lines.append(f"- AI: ⚠️ {ai['error']}")
        lines.append("")

    out = args.output or os.path.join(
        REPORT_DIR, datetime.now(timezone.utc).strftime("%Y%m%d_%H%M") + "_report.md")
    out_dir = os.path.dirname(out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"报告已生成: {out} (含 {tp_total} 个 AI 确认真漏洞)")
    return 0

# ============================================================
# doctor / update
# ============================================================

def cmd_doctor(args):
    checks = []
    # token
    token = load_token()
    checks.append(("GitHub token", "OK" if token else "缺失(匿名限速 10次/分钟)"))
    if token:
        try:
            req = urllib.request.Request("https://api.github.com/rate_limit", headers=_headers())
            with _opener().open(req, timeout=10) as resp:
                rl = json.loads(resp.read())
            core = rl.get("resources", {}).get("search", {})
            checks.append(("GitHub 配额", f"search {core.get('remaining','?')}/{core.get('limit','?')}"))
        except Exception as e:
            checks.append(("GitHub 配额", f"查询失败 {str(e)[:50]}"))
    # AI
    api_key = os.environ.get("WHITESCAN_AI_KEY") or _load_ai_key()
    base_url = os.environ.get("WHITESCAN_AI_BASE", "https://api.b.ai/v1")
    model = os.environ.get("WHITESCAN_AI_MODEL", "glm-5.3-flash")
    if api_key:
        try:
            t0 = time.time()
            verdicts = ai_review("// test", [], base_url, api_key, model)
            checks.append(("AI 深审", f"OK ({time.time()-t0:.1f}s, {model})"))
        except Exception as e:
            checks.append(("AI 深审", f"失败 {str(e)[:60]}"))
    else:
        checks.append(("AI 深审", "未配置(~/.whitescan…/ai_key.txt)"))
    # 输出目录
    os.makedirs(REPORT_DIR, exist_ok=True)
    checks.append(("报告目录", REPORT_DIR))
    print("WhiteScan 自检:")
    for name, status in checks:
        print(f"  {'✅' if 'OK' in status or status.startswith('/') else '⚠️'} {name}: {status}")
    return 0

def _version_key(v):
    """版本号转元组，修复 '1.0.10' < '1.0.9' 的字典序错误"""
    try:
        return tuple(int(x) for x in re.findall(r'\d+', v)[:4])
    except (ValueError, TypeError):
        return (0,)

def cmd_update(args):
    """自更新: 拉远程版本号对比，新版就覆盖自身"""
    try:
        req = urllib.request.Request(VERSION_URL, headers={"User-Agent": "whitescan"})
        with _opener().open(req, timeout=15) as resp:
            remote = resp.read().decode().strip()
    except Exception as e:
        print(f"检查更新失败: {e}")
        return 1
    print(f"本地 v{__version__} / 远程 v{remote}")
    if _version_key(remote) <= _version_key(__version__):
        print("已是最新")
        return 0
    req = urllib.request.Request(SELF_URL, headers={"User-Agent": "whitescan"})
    with _opener().open(req, timeout=30) as resp:
        new_code = resp.read().decode("utf-8")
    me = os.path.abspath(__file__)
    with open(me + ".new", "w", encoding="utf-8") as f:
        f.write(new_code)
    os.replace(me + ".new", me)
    os.chmod(me, 0o755)
    print(f"已更新到 v{remote}, 重新运行生效")
    return 0

# ============================================================
# 规则自测（关键：首存攻击样例必须命中）
# ============================================================

SAMPLE_VULN = """
pragma solidity ^0.7.6;
contract CToken {
    uint public initialExchangeRate = 2e18;
    uint public totalSupply;
    mapping(address => uint) public accountTokens;
    function exchangeRateStored() public view returns (uint) {
        if (totalSupply == 0) { return initialExchangeRate; }
        return totalSupply * 1e18 / totalSupply;
    }
    function mint() external payable { accountTokens[msg.sender] += msg.value; totalSupply += msg.value; }
    function redeem(uint amt) external { payable(msg.sender).call{value: amt}(""); }
}
"""
SAMPLE_FIXED = """
pragma solidity ^0.8.19;
contract CTokenSafe {
    uint public initialExchangeRate = 2e18;
    uint public totalSupply = 1000;
    mapping(address => uint) public accountTokens;
    function exchangeRateStored() public view returns (uint) {
        if (totalSupply == 0) { return initialExchangeRate; }
        return totalSupply * 1e18 / totalSupply;
    }
    constructor() { accountTokens[address(0)] = 1000; }
}
"""
# 新规则样例: ERC4626无虚拟份额 + 回调无验证 + 验签缺保护
SAMPLE_4626 = """
pragma solidity ^0.8.20;
contract Vault4626 is IERC4626 {
    uint public totalSupply;
    function _convertToShares(uint assets) internal view returns (uint) {
        return assets * totalSupply / totalAssets();
    }
}
"""
SAMPLE_CALLBACK_VULN = """
pragma solidity ^0.8.20;
contract FlashUser {
    function executeOperation(address asset, uint amount, uint premium, address initiator, bytes calldata params) external returns (bool) {
        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
}
"""
SAMPLE_CALLBACK_FIXED = """
pragma solidity ^0.8.20;
contract FlashUserSafe {
    address immutable POOL;
    function executeOperation(address asset, uint amount, uint premium, address initiator, bytes calldata params) external returns (bool) {
        require(msg.sender == POOL, "untrusted");
        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
}
"""
SAMPLE_SIG_REPLAY = """
pragma solidity ^0.8.20;
contract Claim {
    function claim(uint amount, bytes calldata sig) external {
        require(amount > 0);
        address signer = ecrecover(keccak256(abi.encode(msg.sender, amount)), 27, sig[:32], sig[32:64], sig[64:]);
    }
}
"""
SAMPLE_SIG_FIXED = """
pragma solidity ^0.8.20;
contract ClaimSafe {
    mapping(bytes32 => bool) used;
    function claim(uint amount, uint deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline);
        require(!used[keccak256(sig)]);
        address signer = ecrecover(keccak256(abi.encode(msg.sender, amount, block.chainid, deadline)), 27, sig[:32], sig[32:64], sig[64:]);
    }
}
"""

def self_test():
    # 1. 首存攻击: 必须命中
    vuln_hits = {h["id"] for h in scan_code(SAMPLE_VULN)}
    assert "COMPOUND-V2-FIRST-DEPOSITOR" in vuln_hits, f"首存攻击样例未命中! 实际: {vuln_hits}"
    # 2. 修复样例: 不许误报
    fixed_hits = {h["id"] for h in scan_code(SAMPLE_FIXED)}
    assert "COMPOUND-V2-FIRST-DEPOSITOR" not in fixed_hits, "修复样例误报!"
    # 3. ERC-4626 通胀
    h4626 = {h["id"] for h in scan_code(SAMPLE_4626)}
    assert "ERC4626-INFLATION" in h4626, f"4626样例未命中! 实际: {h4626}"
    # 4. 回调无验证: 漏洞版命中, 安全版不命中
    hcb = {h["id"] for h in scan_code(SAMPLE_CALLBACK_VULN)}
    assert "UNPROTECTED-CALLBACK" in hcb, f"回调样例未命中! 实际: {hcb}"
    hcb_fix = {h["id"] for h in scan_code(SAMPLE_CALLBACK_FIXED)}
    assert "UNPROTECTED-CALLBACK" not in hcb_fix, "回调安全样例误报!"
    # 5. 签名重放: 漏洞版命中, 安全版不命中
    hsig = {h["id"] for h in scan_code(SAMPLE_SIG_REPLAY)}
    assert "SIGNATURE-REPLAY" in hsig, f"签名样例未命中! 实际: {hsig}"
    hsig_fix = {h["id"] for h in scan_code(SAMPLE_SIG_FIXED)}
    assert "SIGNATURE-REPLAY" not in hsig_fix, "签名安全样例误报!"
    print(f"✅ 规则自测通过({len(VULN_RULES)}条): 首存攻击/4626通胀/回调仿冒/签名重放 全命中, "
          f"3个安全样例 0 误报")

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(prog="whitescan", description="冷门 fork 协议漏洞批量扫描器")
    parser.add_argument("--version", action="version", version=f"WhiteScan {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="批量扫描(GitHub 或本地目录)")
    p_scan.add_argument("--source", choices=["github", "dir"], default="github")
    p_scan.add_argument("--target", help="source=dir 时的目录")
    p_scan.add_argument("--limit", type=int, default=30, help="每个 query 取多少 repo")
    p_scan.set_defaults(func=cmd_scan)

    p_ai = sub.add_parser("ai", help="AI 语义复核 scan 结果")
    p_ai.add_argument("scan_file", nargs="?", default=RESULTS_PATH)
    p_ai.add_argument("--max", type=int, default=10, help="最多审几个项目")
    p_ai.set_defaults(func=cmd_ai)

    p_rep = sub.add_parser("report", help="生成 Markdown 报告")
    p_rep.add_argument("scan_file", nargs="?", default=RESULTS_PATH)
    p_rep.add_argument("-o", "--output")
    p_rep.set_defaults(func=cmd_report)

    sub.add_parser("doctor", help="自检").set_defaults(func=cmd_doctor)
    sub.add_parser("update", help="自更新").set_defaults(func=cmd_update)
    sub.add_parser("selftest", help="规则自测").set_defaults(func=lambda a: self_test() or 0)

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args) or 0

if __name__ == "__main__":
    sys.exit(main())
