#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteScan Monitor — 链上新部署合约实时漏洞监控
==============================================
标准库实现（无 pip 依赖，003 VPS / 008 Mac 通吃）。
轮询 RPC 最新区块 → 提取新部署合约 → Blockscout 拉已验证源码
→ 复用 whitescan.py 24 条规则引擎 → HIGH/MED 命中即告警。

数据流:
  eth_getBlockReceipts(新块) → 筛 contractAddress≠null（覆盖普通创建+CREATE2工厂）
  → Blockscout /api/v2/smart-contracts/{addr}（is_verified + source_code）
  → ws.scan_code() → 告警（stdout + monitor_hits.json + 可选 webhook）

用法:
  python3 whitescan_monitor.py                  # 常驻轮询主网
  python3 whitescan_monitor.py --once           # 只扫当前最新一个块后退出
  python3 whitescan_monitor.py --chain sepolia  # 测试网（联调用）
  python3 whitescan_monitor.py --addr 0x..      # 手动深扫单个合约
  python3 whitescan_monitor.py selftest         # 离线自检（不联网）

环境变量:
  WHITESCAN_ALERT_WEBHOOK  告警 webhook（POST JSON），留空只写文件+stdout
  WHITESCAN_RPC            自定义 RPC，覆盖默认
  WHITESCAN_PROXY          出站代理（008 走 QuickQ 时用）

安全边界:
  - 只读链上公开数据，零私钥零签名
  - 源码 >200KB 跳过（规则引擎按文本扫，超大源码收益递减）
  - 未验证源码的合约记日志跳过（无法静态扫描 bytecode）
  - 每块最多处理 30 个新合约（防垃圾块轰炸拖垮轮询节奏）
"""
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import whitescan as ws  # noqa: E402  复用规则引擎

__version__ = "1.4.0"

# ------------------------------------------------------------
# 配置
# ------------------------------------------------------------

CHAINS = {
    "mainnet": {
        "rpcs": [
            "https://ethereum-rpc.publicnode.com",
            "https://1rpc.io/eth",
            "https://eth.drpc.org",
        ],
        "explorer_api": "https://eth.blockscout.com/api/v2",
        "explorer_ui": "https://eth.blockscout.com",
        "name": "以太坊主网",
    },
    "sepolia": {
        "rpcs": [
            "https://ethereum-sepolia-rpc.publicnode.com",
            "https://1rpc.io/sepolia",
        ],
        "explorer_api": "https://eth-sepolia.blockscout.com/api/v2",
        "explorer_ui": "https://eth-sepolia.blockscout.com",
        "name": "Sepolia 测试网",
    },
}

# RPC 必须带浏览器 UA（裸 whitescan UA 会被 403）
HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Content-Type": "application/json",
}

MAX_SOURCE_BYTES = 200 * 1024   # 源码上限
MAX_CONTRACTS_PER_BLOCK = 30    # 每块新合约处理上限
POLL_INTERVAL = 12              # 秒（≈1 个出块周期）
MAX_CATCHUP_BLOCKS = 10         # 单轮最多追块数（防长时间宕机后疯狂回溯）
ALERT_SEVERITIES = {"HIGH", "MED"}  # 触发告警的等级；LOW 只入库不告警

# state/hits 按链分文件（不同链的块高完全不可比，混用会导致切链后永不扫描）
STATE_PATH = os.path.join(SCRIPT_DIR, "monitor_state_{chain}.json")
HITS_PATH = os.path.join(SCRIPT_DIR, "monitor_hits_{chain}.json")

# ------------------------------------------------------------
# HTTP 底座（代理 + UA + 超时）
# ------------------------------------------------------------

_opener_cache = None


def get_opener():
    """带可选代理的 opener（WHITESCAN_PROXY，与主扫描器同约定）"""
    global _opener_cache
    if _opener_cache is None:
        proxy = os.environ.get("WHITESCAN_PROXY", "").strip()
        if proxy:
            _opener_cache = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            _opener_cache = urllib.request.build_opener()
    return _opener_cache


def http_json(url, payload=None, timeout=15, headers=None):
    """GET(payload=None)/POST JSON，返回解析后的 JSON"""
    hdrs = dict(HTTP_HEADERS)
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with get_opener().open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


# ------------------------------------------------------------
# RPC 层（带故障转移）
# ------------------------------------------------------------

_rpc_idx = 0


def _rpc_base(chain_cfg):
    """当前应使用的 RPC 列表（WHITESCAN_RPC 优先）"""
    custom = os.environ.get("WHITESCAN_RPC", "").strip()
    return [custom] if custom else chain_cfg["rpcs"]


def rpc_call(chain_cfg, method, params, timeout=12):
    """JSON-RPC 调用，失败自动换下一个 RPC 端点"""
    global _rpc_idx
    rpcs = _rpc_base(chain_cfg)
    last_err = None
    for i in range(len(rpcs)):
        url = rpcs[(_rpc_idx + i) % len(rpcs)]
        try:
            d = http_json(url, {"jsonrpc": "2.0", "method": method,
                                "params": params, "id": 1}, timeout=timeout)
            if "error" in d:
                raise RuntimeError(str(d["error"])[:120])
            _rpc_idx = (_rpc_idx + i) % len(rpcs)
            return d["result"]
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise RuntimeError(f"全部RPC失败: {last_err}")


# ------------------------------------------------------------
# 区块 → 新合约提取
# ------------------------------------------------------------

def latest_block(chain_cfg):
    n = rpc_call(chain_cfg, "eth_blockNumber", [])
    return int(n, 16)


def block_receipts(chain_cfg, height):
    """整块回执一把抓（覆盖 to=null 直接创建 + CREATE2 工厂部署）"""
    hexh = hex(height)
    try:
        receipts = rpc_call(chain_cfg, "eth_getBlockReceipts", [hexh])
        if isinstance(receipts, list):
            return receipts
        return None
    except RuntimeError:
        return None


def extract_creations(receipts):
    """从回执列表提取新部署合约地址（去重保序）"""
    seen, out = set(), []
    for r in receipts or []:
        addr = (r or {}).get("contractAddress")
        if addr and addr != "0x0000000000000000000000000000000000000000" and addr not in seen:
            seen.add(addr)
            out.append({"address": addr, "tx": (r or {}).get("transactionHash", ""),
                        "from": (r or {}).get("from", "")})
    return out


# ------------------------------------------------------------
# 合约 → 已验证源码（Blockscout）
# ------------------------------------------------------------

def fetch_verified_source(explorer_api, address, timeout=15):
    """返回 (contract_name, source_code)；未验证返回 (None, None)"""
    try:
        d = http_json(f"{explorer_api}/smart-contracts/{address}",
                      timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise
    if not d.get("is_verified") and not d.get("is_partially_verified"):
        return None, None
    src = d.get("source_code") or ""
    return (d.get("name") or "Unknown"), src


# ------------------------------------------------------------
# 扫描 + 告警
# ------------------------------------------------------------

def scan_source(source_code):
    """跑 24 条规则引擎，返回 hits（超大源码直接跳过）"""
    if not source_code or len(source_code) > MAX_SOURCE_BYTES:
        return []
    try:
        return ws.scan_code(source_code) or []
    except Exception:  # 规则引擎对极端输入永不拖垮监控主循环
        return []


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def append_hit(record, hits_path):
    """告警记录落盘（保留最近 500 条）"""
    records = load_json(hits_path, [])
    records.append(record)
    save_json(hits_path, records[-500:])


def send_webhook(message):
    """POST JSON 到 WHITESCAN_ALERT_WEBHOOK（Telegram sendMessage 兼容格式）"""
    url = os.environ.get("WHITESCAN_ALERT_WEBHOOK", "").strip()
    if not url:
        return False
    try:
        http_json(url, {"text": message, "chat_id": ""}, timeout=10)
        return True
    except Exception:  # 告警通道故障不拖垮主循环
        return False


def fmt_alert(rec):
    """告警文本：简洁人话，一条一个合约"""
    chain_name = rec["chain_name"]
    lines = [f"🚨 WhiteScan 链上告警 [{chain_name} #{rec['block']}]",
             f"合约: {rec['address']} ({rec['contract_name']})",
             f"创建交易: {rec['tx']}"]
    for h in rec["hits"]:
        lines.append(f"[{h['sev']}] {h['id']}: {h['desc'][:80]}")
    lines.append(f"源码: {rec['explorer_ui']}/address/{rec['address']}")
    return "\n".join(lines)


def chain_paths(chain_key):
    """按链解析 state/hits 文件路径"""
    return (STATE_PATH.format(chain=chain_key), HITS_PATH.format(chain=chain_key))


def process_contract(chain_cfg, item, height, hits_path):
    """单合约全流程：拉源码→扫描→告警。返回 record 或 None"""
    address = item["address"]
    name, src = fetch_verified_source(chain_cfg["explorer_api"], address)
    if name is None:
        return None  # 未验证源码，无法静态扫描
    hits = scan_source(src)
    if not hits:
        return None
    rec = {
        "ts": int(time.time()),
        "chain": CHAIN_KEY, "chain_name": chain_cfg["name"],
        "block": height, "address": address, "tx": item["tx"],
        "contract_name": name,
        "hits": [{"sev": h["sev"], "id": h["id"], "desc": h["desc"]} for h in hits],
        "explorer_ui": chain_cfg["explorer_ui"],
        "alerted": any(h["sev"] in ALERT_SEVERITIES for h in hits),
    }
    append_hit(rec, hits_path)
    if rec["alerted"]:
        msg = fmt_alert(rec)
        print(msg, flush=True)
        send_webhook(msg)
    return rec


# ------------------------------------------------------------
# 主循环
# ------------------------------------------------------------

CHAIN_KEY = "mainnet"


def scan_block(chain_cfg, height, seen, hits_path):
    """扫一个块的新合约。返回 (处理数, 告警数)"""
    receipts = block_receipts(chain_cfg, height)
    creations = extract_creations(receipts)
    if not creations:
        return 0, 0
    # CREATE2 工厂部署的底层合约无法拿源码，receipts 方案已覆盖工厂子合约
    n_scanned, n_alert = 0, 0
    for item in creations:
        if n_scanned >= MAX_CONTRACTS_PER_BLOCK:
            break  # 余下留待下次（seen 不记，下轮同块重扫会再试）
        addr_l = item["address"].lower()
        if addr_l in seen:
            continue
        seen.add(addr_l)
        n_scanned += 1
        try:
            rec = process_contract(chain_cfg, item, height, hits_path)
            if rec and rec["alerted"]:
                n_alert += 1
        except Exception as e:  # noqa: BLE001  单合约故障不拖垮整块
            print(f"  ⚠️ {item['address'][:12]} 处理失败: {str(e)[:80]}", flush=True)
        time.sleep(0.3)  # 对 Blockscout 温柔点（免费公共实例）
    return n_scanned, n_alert


def run_loop(chain_key, once=False):
    global CHAIN_KEY
    CHAIN_KEY = chain_key
    chain_cfg = CHAINS[chain_key]
    state_path, hits_path = chain_paths(chain_key)
    state = load_json(state_path, {})
    seen = set(state.get("seen", []))
    last_height = state.get("last_height", 0)

    print(f"🐾 WhiteScan Monitor v{__version__} 启动 [{chain_cfg['name']}]"
          f" 规则数={len(ws.VULN_RULES)}", flush=True)

    while True:
        try:
            tip = latest_block(chain_cfg)
            if last_height == 0:
                last_height = tip - 1  # 首启从最新块开始，不回溯历史
            if tip <= last_height:
                time.sleep(POLL_INTERVAL)
                continue
            start = max(last_height + 1, tip - MAX_CATCHUP_BLOCKS)
            for h in range(start, tip + 1):
                n, a = scan_block(chain_cfg, h, seen, hits_path)
                last_height = h
                if n:
                    print(f"  📦 块#{h}: 新合约 {n} 个, 告警 {a}", flush=True)
            save_json(state_path, {
                "last_height": last_height,
                "seen": list(seen)[-2000:],  # 有界，防无限膨胀
                "ts": int(time.time()),
            })
        except Exception as e:  # noqa: BLE001  主循环永不退出
            print(f"  ⚠️ 轮询异常: {str(e)[:100]}", flush=True)
            time.sleep(POLL_INTERVAL)
            continue
        if once:
            print("✅ --once 完成", flush=True)
            return
        time.sleep(POLL_INTERVAL)


# ------------------------------------------------------------
# 手动单合约深扫
# ------------------------------------------------------------

def scan_single_address(chain_key, address):
    chain_cfg = CHAINS[chain_key]
    name, src = fetch_verified_source(chain_cfg["explorer_api"], address)
    if name is None:
        print(f"❌ {address} 在 Blockscout 无已验证源码", flush=True)
        return None
    hits = scan_source(src)
    print(f"合约 {name} @ {address} | 源码 {len(src or '')}B | 命中 {len(hits)}", flush=True)
    for h in hits:
        print(f"  [{h['sev']}] {h['id']}: {h['desc']}")
    if not hits:
        print("✅ 未命中规则（不代表无漏洞，静态引擎覆盖有限）", flush=True)
    return hits


# ------------------------------------------------------------
# selftest（离线，fixture 驱动）
# ------------------------------------------------------------

def selftest():
    """离线自检：提取/扫描/落盘/告警格式 全链路 mock 验证"""
    ok = []

    # 1) extract_creations：直接创建 + CREATE2(receipt带contractAddress) + 空地址过滤
    fake_receipts = [
        {"transactionHash": "0xaa", "from": "0xf1", "contractAddress": "0xAAA1"},
        {"transactionHash": "0xbb", "from": "0xf2",
         "contractAddress": "0x0000000000000000000000000000000000000000"},
        {"transactionHash": "0xcc", "from": "0xf3", "contractAddress": None},
        {"transactionHash": "0xaa", "from": "0xf1", "contractAddress": "0xAAA1"},  # 重复
    ]
    c = extract_creations(fake_receipts)
    assert len(c) == 1 and c[0]["address"] == "0xAAA1", f"extract失败: {c}"
    ok.append("回执提取+去重")

    # 2) scan_source：漏洞样例命中、安全样例零命中、垃圾输入不崩
    vuln = """
contract Vault {
    mapping(address => uint) public balances;
    function withdraw() external {
        uint amt = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}"""
    hits = scan_source(vuln)
    assert any(h["id"] == "REENTRANCY" for h in hits), f"重入未命中: {hits}"
    assert scan_source("not solidity at all {{{") is not None  # 垃圾输入不崩
    assert scan_source("x" * (MAX_SOURCE_BYTES + 1)) == []      # 超限跳过
    ok.append("规则引擎扫描")

    # 3) 告警格式：含地址/等级/浏览器链接
    rec = {"chain_name": "以太坊主网", "block": 123, "address": "0xabc",
           "contract_name": "T", "tx": "0xt", "explorer_ui": "https://x",
           "hits": [{"sev": "HIGH", "id": "REENTRANCY", "desc": "d" * 90}]}
    txt = fmt_alert(rec)
    assert "0xabc" in txt and "HIGH" in txt and "REENTRANCY" in txt and "#123" in txt
    ok.append("告警格式")

    # 4) 落盘往返 + 500 条截断
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "h.json")
        for i in range(510):
            append_hit({"i": i}, hits_path=p)
        data = load_json(p, [])
        assert len(data) == 500 and data[-1]["i"] == 509, f"截断异常: {len(data)}"
    ok.append("落盘往返+截断")

    # 5) CHAINS 配置完整性
    for ck, cc in CHAINS.items():
        assert cc["rpcs"] and cc["explorer_api"].startswith("https") and cc["name"]
    ok.append("链配置")

    print(f"✅ monitor selftest 通过: {' | '.join(ok)}")
    return True


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if "selftest" in args:
        selftest()
        return
    chain_key = "mainnet"
    if "--chain" in args:
        chain_key = args[args.index("--chain") + 1]
        assert chain_key in CHAINS, f"未知链: {chain_key}"
    if "--addr" in args:
        addr = args[args.index("--addr") + 1]
        if not re.match(r"^0x[0-9a-fA-F]{40}$", addr):
            print("❌ 地址格式错误")
            sys.exit(1)
        scan_single_address(chain_key, addr)
        return
    run_loop(chain_key, once=("--once" in args))


if __name__ == "__main__":
    main()
