#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteScan v1.2.0 — 冷门 fork 协议批量漏洞扫描器
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

__version__ = "1.5.0"
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
    has_call = re.search(r'\.call\{value:|\.call\(|\.delegatecall\(', code)
    has_guard = re.search(r'nonReentrant|ReentrancyGuard|_notEntered|_status\s*=', code)
    if not has_call or has_guard:
        return None
    # CEI违例判定: 外部调用之后仍有状态写(余额清零/记账) = 经典重入可利用点
    # call前写完再call(检查-生效-交互)是安全模式, 不报
    write_pat = re.compile(
        r'^\s*(?!(?:uint\d*|int\d*|bool|address\s*(?:payable)?\s+\w+\s*=|bytes\d*|string|mapping|IERC\d*|enum|struct|function|require|emit|return|if|for|while|delete)\b)'
        r'(\w+)\s*(?:\[[^\]]*\])?\s*(?:\+=|-=|\*=|/=|\^=|=)(?!=)\s*[^;]+;', re.M)
    for m in re.finditer(r'\.call\{value:|\.call\(|\.delegatecall\(', code):
        fend = code.find('function', m.end())
        after = code[m.end():fend if fend > 0 else len(code)]
        # 截到函数体结束(第一个^}行)
        brace_end = after.find('\n}')
        if brace_end > 0:
            after = after[:brace_end]
        writes = [w for w in write_pat.findall(after)
                  if w not in ('success', 'ok', 'data', 'result')]
        if writes:
            return "外部调用后仍有状态写入且无重入保护(CEI违例, 经典重入)"
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
    if not re.search(r'\.call\(', code):
        return None
    # 守卫按语句分界(;)识别, 兼容: require(x.call(..), "err") / bool ok = x.call(..); require(ok) / if(!success)
    guard = re.search(
        r'require\([^;]*?\.call\s*\('
        r'|require\([^;]*?\b(?:ok|success)\b'
        r'|\b(?:ok|success)\s*=\s*[^;]*?\.call\s*\('
        r'|if\s*\(\s*!?\s*(?:ok|success)\s*\)', code)
    if not guard:
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

def detect_timelock_zero(code):
    """Timelock清零(2026-08 Term Finance $8.5M): 治理可把delay设为0, 提案即时执行无缓冲"""
    if not re.search(r'timelock|Timelock|delay|DELAY|gracePeriod|minDelay', code):
        return None
    # 危险特征: delay/duration 作为状态变量可被 setter 改, 且无下限约束
    if re.search(r'function\s+set\w*(Delay|Timelock|Duration)\s*\(', code):
        # setter 内无 >= 下限检查(如 require(newDelay >= 1 days))
        m = re.search(r'function\s+set\w*(Delay|Timelock|Duration)\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}', code)
        if m and not re.search(r'>=\s*\d|MIN(?:imum)?_?DELAY|MINIMUM_DELAY|minDelay', m.group(2)):
            return "timelock delay 可经 setter 设为 0，恶意提案可即时执行(Term Finance模式)"
    if re.search(r'(delay|Duration|Timelock)\s*=\s*0\b', code) and not re.search(r'MIN|require', code):
        return "timelock delay 初始化为 0"
    return None

def detect_crosschain_sig_replay(code):
    """跨链消息签名重放(2026-06 桥$127M): 验签缺 chainId/srcChain/nonce, 一链签名他链重放"""
    if not re.search(r'ecrecover\s*\(|validateProof|verifySignature|checkSignatures', code):
        return None
    ctx_hint = re.search(r'(srcChain|sourceChain|destChain|dstChain|crossChain|bridge|remoteChain|fromChain)', code, re.I)
    if not ctx_hint:
        return None  # 非跨链场景, 交给 SIGNATURE-REPLAY
    has_chainid = re.search(r'block\.chainid|chainId|srcChainId|sourceChainId|CHAIN_ID', code)
    has_nonce = re.search(r'nonce|sequence|usedHash|consumed', code, re.I)
    missing = [n for n, ok in (("chainId", has_chainid), ("nonce", has_nonce)) if not ok]
    if missing:
        return f"跨链消息验签缺 {'/'.join(missing)}，签名可跨链/跨序重放(2026-06桥失窃$127M模式)"
    return None

def detect_hardcoded_auth_secret(code):
    """硬编码认证串(2026-05 SquidRouterModule $3.2M): 固定字符串当消息鉴权, 泄露即资产可取"""
    # 形态1: keccak256(abi.encodePacked("literal...")) 参与比较/鉴权
    if re.search(r'keccak256\s*\(\s*abi\.encodePacked\s*\(\s*"[^"]{8,}"\s*\)\s*\)', code):
        return "硬编码字符串哈希用于鉴权，泄露即伪造(SquidRouterModule $3.2M模式)"
    # 形态2: require(keccak256(bytes("literal")) == ...)
    if re.search(r'keccak256\s*\(\s*bytes\s*\(\s*"[^"]{8,}"\s*\)\s*\)', code):
        return "硬编码字符串哈希用于鉴权，泄露即伪造(SquidRouterModule $3.2M模式)"
    return None

def detect_legacy_live_contract(code):
    """遗留合约仍在服务(2026-05 Transit Finance $1.88M): deprecated/legacy 合约未弃用, 弱校验可调用"""
    if re.search(r'deprecated|legacy|old contract|use \w+ instead|@notice\s*.*(deprecated|do not use)', code, re.I):
        # 弃用合约里还有外部可调入口
        if re.search(r'function\s+\w+\s*\([^)]*\)\s*(?:external|public)', code) and \
           not re.search(r'revert\s*\(\s*["\']?deprecated|selfdestruct|onlyOwner|pause', code, re.I):
            return "合约标记 deprecated/legacy 但入口仍可调用且无熔断(Transit Finance $1.88M模式)"
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
    # 只关心ERC20的transfer/send: payable(x).transfer/send是原生币转账(失败自动revert, 无返回值问题)
    erc20_calls = [m for m in re.finditer(r'\.transfer\(|\.send\(', code)
                   if not re.search(r'payable\s*\([^)]*\)\s*\.(?:transfer|send)\s*\(', code[max(0,m.start()-60):m.end()+20])]
    if not erc20_calls:
        return None
    # 逐调用点检查同语句(至下个;)是否有守卫: require(...)/bool v = .../if(!v).../v = ...
    guard = re.compile(
        r'(?:require\s*\([^;]*?|\b\w+\s*=\s*(?:bool\s+)?[^;]*?)\.(?:transfer|send)\s*\('
        r'|if\s*\([^;]*?\.(?:transfer|send)\s*\(')
    for m in erc20_calls:
        stmt_start = code.rfind(';', 0, m.start()) + 1
        stmt_end = code.find(';', m.end())
        stmt = code[stmt_start:stmt_end if stmt_end > 0 else len(code)]
        if not guard.search(stmt):
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

def detect_tax_burn_from_pool(code):
    """通缩税代币在 _transfer 卖出路径烧池子余额 + 主动 sync 池子 (FH Token 2026-08-26 $20K 模式)。
    三特征同时命中才报: ①DEAD/零地址烧币 ②引用 AMM pair 变量 ③合约内调 sync()"""
    if len(code) > 400000:
        return None
    has_dead = bool(re.search(r"0x[0-9a-fA-F]{38,40}[dD][eE][aA][dD]|\bdead\b|DEAD", code))
    has_pair = bool(re.search(r"pair|Pair\s*\(|_pair|IPancakePair|IUniswapV2Pair", code))
    has_sync = bool(re.search(r"\.sync\s*\(\s*\)", code))
    # 烧币来源必须是 pair/池子而不是 sender: pair.balance 或 balanceOf(pair) 或 transfer(dead) 前取 pair 余额
    burn_pair = bool(re.search(r"(_burn\s*\(\s*pair|_transfer\s*\(\s*pair|balanceOf\s*\(\s*(pair|address\s*\(\s*this\s*\))|balances\s*\[\s*(pair|address\s*\(\s*pair\s*\))|pair\s*\.\s*balance)", code, re.I))
    if has_dead and has_pair and has_sync and burn_pair:
        return ("通缩税代币在转账路径烧 AMM pair 余额并立即 sync(): 卖出税从池子扣而非卖方扣, "
                "每次卖出烧掉流动性后备; 买卖循环可单笔内重复抽干 (FH Token 2026-08-26 $20K 实战)")
    return None

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
    ("TIMELOCK-ZERO",               "治理timelock可清零",       "HIGH",   detect_timelock_zero),
    ("CROSSCHAIN-SIG-REPLAY",       "跨链消息签名重放",         "HIGH",   detect_crosschain_sig_replay),
    ("HARDCODED-AUTH-SECRET",       "硬编码鉴权串",             "MED",    detect_hardcoded_auth_secret),
    ("LEGACY-LIVE-CONTRACT",        "弃用合约仍可调用",         "LOW",    detect_legacy_live_contract),
    ("TAX-BURN-FROM-POOL",          "通缩税烧池子+主动sync",    "HIGH",   detect_tax_burn_from_pool),
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
    """优先猜常见路径(并发探测省时)，猜不中就列根目录模糊匹配借贷协议文件"""
    from concurrent.futures import ThreadPoolExecutor
    keywords = ("CToken", "Comptroller", "Lending", "Lend", "Market", "Pool",
                "Controller", "Bank", "Vault", "Borrow")
    # 先列根目录(1次API): 命中关键词直接取, 大多数fork走这条路
    listing = gh_repo_root_listing(repo) or []
    cand = [item for item in listing
            if item.endswith(".sol") and any(k.lower() in item.lower() for k in keywords)]
    for item in cand:
        code = gh_file_raw(repo, item)
        if code:
            return item, code
    # 根目录无果再并发猜常见路径(子目录 contracts/ src/)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda p: (p, gh_file_raw(repo, p)), TOKEN_PATHS))
    for path, code in results:
        if code:
            return path, code
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
        "uniswap v2 fork language:Solidity stars:<50",
        "pancakeswap fork language:Solidity stars:<50",
        "masterchef vault solidity language:Solidity stars:<50",
        "yield farming staking solidity language:Solidity stars:<30",
        "presale token sale solidity language:Solidity stars:<30",
        "bridge locker solidity language:Solidity stars:<30",
        "price oracle solidity language:Solidity stars:<30",
        "governance timelock solidity language:Solidity stars:<30",
        "token vesting solidity language:Solidity stars:<30",
        "multisig wallet solidity language:Solidity stars:<30",
    ]

def cmd_scan(args):
    """主扫描流程: GitHub 搜索 → 逐 repo 初筛 → 结果落盘（可选 --ai 直连复核）"""
    source = getattr(args, "source", "github")
    target = getattr(args, "target", None)
    limit = getattr(args, "limit", 50)
    repos = []  # (repo, stars, path, hits)

    if source == "dir":
        if not target or not os.path.isdir(target):
            print(json.dumps({"error": f"目录不存在: {target}"}, ensure_ascii=False))
            return 2
        for root, _dirs, files in os.walk(target):  # 递归子目录
            for fn in sorted(files):
                if not fn.endswith(".sol"):
                    continue
                p = os.path.join(root, fn)
                try:
                    code = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                hits = scan_code(code)
                if hits:
                    print(f"🔴 {os.path.relpath(p, target)}")
                    for h in hits:
                        print(f"   └─ [{h['sev']}] {h['id']}: {h['desc']}")
                    repos.append((os.path.relpath(p, target), 0, p, hits))
        out = [{"repo": r[0], "stars": 0, "file": r[2], "hits": r[3]} for r in repos]
        _save_results(out)
        print(f"\n=== 完成: 扫描目录 {target}, 命中 {len(out)} (落盘 {RESULTS_PATH}) ===")
        return _maybe_ai_after_scan(args, out)

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
    return _maybe_ai_after_scan(args, out)

def _save_results(records):
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"version": __version__, "ts": _now(), "results": records}, f, indent=2, ensure_ascii=False)

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ============================================================
# AI 语义深审层（b.ai 免费 glm-5.3）
# ============================================================

def _http_json(req, timeout, retries=3):
    """带重试的 HTTP JSON 请求: 网络/5xx/429 指数退避重试, 4xx 直接失败"""
    last_err = None
    for attempt in range(retries):
        try:
            with _opener().open(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 and e.code != 429:
                raise  # 客户端错误(key错/参数错)重试无意义
            last_err = f"HTTP {e.code}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:80]}"
        if attempt < retries - 1:
            wait = 2 ** attempt * 2  # 2s, 4s
            print(f"  [请求失败({last_err}), {wait}s 后重试 {attempt+2}/{retries}]", flush=True)
            time.sleep(wait)
    raise RuntimeError(f"重试{retries}次仍失败: {last_err}")

def ai_review(code, hits, base_url, api_key, model):
    """调 OpenAI 兼容 API 让大模型复核命中，返回 verdict 列表（含重试+退避）"""
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
    data = _http_json(req, timeout=AI_TIMEOUT)
    content = data["choices"][0]["message"].get("content") or ""
    if not content.strip():
        raise ValueError("AI 输出为空(推理耗尽输出预算)，加大 max_tokens 或换模型")
    # glm 推理模型可能带 ```json 包裹，剥掉
    m = re.search(r'\{[\s\S]*\}', content)
    if not m:
        raise ValueError(f"AI 返回无 JSON: {content[:200]}")
    parsed = json.loads(m.group(0))
    return parsed.get("verdicts", [])

def _maybe_ai_after_scan(args, records):
    """scan --ai: 扫完直接对命中项目跑 AI 复核（复用 cmd_ai 逻辑）"""
    if not getattr(args, "ai", False) or not records:
        return 0
    print(f"\n=== 直连 AI 复核 (前 {getattr(args, 'max', 10) or 10} 项) ===", flush=True)
    ns = argparse.Namespace(scan_file=RESULTS_PATH, max=getattr(args, "max", 10),
                            min_sev=getattr(args, "min_sev", "HIGH"))
    return cmd_ai(ns)

def cmd_ai(args):
    """对 scan 结果做 AI 复核，只审 HIGH 或 --all/--min-sev 指定级别"""
    path = args.scan_file
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    records = data.get("results", data) if isinstance(data, dict) else data

    min_sev = getattr(args, "min_sev", "HIGH") or "HIGH"
    if min_sev == "ALL":
        targets = records
    elif min_sev == "HIGH":
        targets = [r for r in records if any(h.get("sev") == "HIGH" for h in r.get("hits", []))]
    else:  # MED: HIGH + MED
        targets = [r for r in records
                   if any(h.get("sev") in ("HIGH", "MED") for h in r.get("hits", []))]
    skipped = len(records) - len(targets)
    if skipped:
        print(f"[按严重级 {min_sev} 过滤: 审 {len(targets)} 项, 跳过 {skipped} 项]", flush=True)

    base_url = os.environ.get("WHITESCAN_AI_BASE", "https://api.b.ai/v1")
    api_key = os.environ.get("WHITESCAN_AI_KEY") or _load_ai_key()
    model = os.environ.get("WHITESCAN_AI_MODEL", "glm-5.3-flash")
    if not api_key:
        print(json.dumps({"error": "缺 AI key: 设 WHITESCAN_AI_KEY 或 ~/whitescan/ai_key.txt"}, ensure_ascii=False))
        return 2

    max_n = getattr(args, "max", 10) or 10
    reviewed = 0
    for rec in targets[:max_n]:
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
# 规则自测矩阵（每条规则: 漏洞样例必中 + 安全样例零误报）
SAMPLE_ORACLE_V = """
pragma solidity ^0.8.19;
contract OracleUser {
    IUniswapV2Pair immutable pair;
    function tokenPrice() external view returns (uint) {
        (uint r0, uint r1, ) = pair.getReserves();
        return r1 * 1e18 / r0;
    }
}
"""
SAMPLE_ORACLE_S = """
pragma solidity ^0.8.19;
contract OracleUserSafe {
    AggregatorV3Interface immutable feed;
    function tokenPrice() external view returns (uint) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return uint256(answer);
    }
}
"""
SAMPLE_INITIALIZER_V = """
pragma solidity ^0.8.19;
contract Market {
    address public admin;
    function initialize(address _admin) external { admin = _admin; }
}
"""
SAMPLE_INITIALIZER_S = """
pragma solidity ^0.8.19;
contract MarketSafe {
    address public admin;
    function initialize(address _admin) external initializer { admin = _admin; }
}
"""
SAMPLE_DELEGATE_V = """
pragma solidity ^0.8.19;
contract Executor {
    function execute(address target, bytes calldata data) external nonReentrant {
        target.delegatecall(abi.encodeWithSignature("mint(address,uint256)", msg.sender, 1e24));
    }
}
"""
SAMPLE_DELEGATE_S = """
pragma solidity ^0.8.19;
contract ExecutorSafe {
    address immutable ROUTER;
    constructor(address router) { ROUTER = router; }
    function execute(bytes calldata data) external nonReentrant {
        ROUTER.delegatecall(data);
    }
}
"""
SAMPLE_MINT_V = """
pragma solidity ^0.8.19;
contract Gold {
    uint public totalSupply;
    mapping(address => uint) public balanceOf;
    function mint(address to, uint amt) external {
        balanceOf[to] += amt;
        totalSupply += amt;
    }
}
"""
SAMPLE_MINT_S = """
pragma solidity ^0.8.19;
contract GoldSafe {
    uint public totalSupply;
    mapping(address => uint) public balanceOf;
    function mint(address to, uint amt) external onlyOwner {
        balanceOf[to] += amt;
        totalSupply += amt;
    }
}
"""
SAMPLE_REENTRANCY_V = """
pragma solidity ^0.8.19;
contract Vault {
    mapping(address => uint) public balances;
    function withdraw() external {
        uint amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
"""
SAMPLE_REENTRANCY_S = """
pragma solidity ^0.8.19;
contract VaultSafe {
    mapping(address => uint) public balances;
    function withdraw() external nonReentrant {
        uint amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
"""
SAMPLE_KILL_V = """
pragma solidity ^0.8.19;
contract Legacy {
    function kill() external { selfdestruct(payable(msg.sender)); }
}
"""
SAMPLE_KILL_S = """
pragma solidity ^0.8.19;
contract LegacySafe {
    address owner;
    function kill() external onlyOwner { selfdestruct(payable(owner)); }
}
"""
SAMPLE_UCALL_V = """
pragma solidity ^0.8.19;
contract Notifier {
    function notify(address to, bytes calldata data) external nonReentrant {
        to.call(data);
    }
}
"""
SAMPLE_UCALL_S = """
pragma solidity ^0.8.19;
contract NotifierSafe {
    function notify(address to, bytes calldata data) external nonReentrant {
        (bool ok, ) = to.call(data);
        require(ok, "notify failed");
    }
}
"""
SAMPLE_OVERFLOW_V = """
pragma solidity ^0.7.6;
contract OldToken {
    uint public totalSupply;
    function burn(uint amt) external { totalSupply -= amt; }
}
"""
SAMPLE_OVERFLOW_S = """
pragma solidity ^0.7.6;
import "./SafeMath.sol";
contract OldTokenSafe {
    using SafeMath for uint256;
    uint public totalSupply;
    function burn(uint amt) external { totalSupply = totalSupply.sub(amt); }
}
"""
SAMPLE_PROXY_V = """
pragma solidity ^0.8.19;
contract VaultProxy {
    address public admin;
    address immutable implementation;
    function initialize(address _admin) external initializer { admin = _admin; }
    fallback() external payable { implementation.delegatecall(msg.data); }
}
"""
SAMPLE_PROXY_S = """
pragma solidity ^0.8.19;
contract VaultProxySafe {
    address immutable implementation;
    constructor(address impl) { implementation = impl; }
    fallback() external payable { implementation.delegatecall(msg.data); }
}
"""
SAMPLE_TXORIGIN_V = """
pragma solidity ^0.8.19;
contract Auth {
    address owner;
    function claim() external {
        require(tx.origin == owner, "not owner");
    }
}
"""
SAMPLE_TXORIGIN_S = """
pragma solidity ^0.8.19;
contract AuthSafe {
    address owner;
    function claim() external {
        require(msg.sender == owner, "not owner");
    }
}
"""
SAMPLE_ZERO_V = """
pragma solidity ^0.8.19;
contract FeeConfig {
    address feeRecipient;
    function setFeeRecipient(address who) external onlyOwner { feeRecipient = who; }
}
"""
SAMPLE_ZERO_S = """
pragma solidity ^0.8.19;
contract FeeConfigSafe {
    address feeRecipient;
    function setFeeRecipient(address who) external onlyOwner {
        require(who != address(0), "zero addr");
        feeRecipient = who;
    }
}
"""
SAMPLE_TS_V = """
pragma solidity ^0.8.19;
contract DrawGame {
    address[] players;
    function drawWinner() external returns (address) {
        uint idx = block.timestamp % players.length;
        return players[idx];
    }
}
"""
SAMPLE_TS_S = """
pragma solidity ^0.8.19;
contract OracleLib {
    function isFresh(uint lastUpdated) external view returns (bool) {
        return block.timestamp - lastUpdated <= 3600;
    }
}
"""
SAMPLE_UTRANSFER_V = """
pragma solidity ^0.8.19;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
contract Distributor {
    IERC20 public token;
    function payout(address to, uint amt) external nonReentrant {
        token.transfer(to, amt);  // 返回值丢弃, 失败静默
    }
}
"""
SAMPLE_UTRANSFER_S = """
pragma solidity ^0.8.19;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
contract DistributorSafe {
    IERC20 public token;
    function payout(address to, uint amt) external nonReentrant {
        require(token.transfer(to, amt), "payout failed");  // 返回值已检查
    }
}
"""
SAMPLE_4626_SAFE = """
pragma solidity ^0.8.20;
contract Vault4626Safe is IERC4626 {
    uint public totalSupply;
    uint constant DECIMAL_OFFSET = 6;
    function _convertToShares(uint assets) internal view returns (uint) {
        return assets * (totalSupply + 10 ** DECIMAL_OFFSET) / totalAssets();
    }
}
"""
SAMPLE_RAND_V = """
pragma solidity ^0.8.19;
contract SeedGame {
    address[] players;
    function winner() external view returns (address) {
        uint seed = uint(keccak256(abi.encodePacked(block.difficulty, block.number, players.length)));
        return players[seed % players.length];
    }
}
"""
SAMPLE_RAND_S = """
pragma solidity ^0.8.19;
contract SeedGameSafe {
    address[] players;
    mapping(uint256 => address) winners;
    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal {
        winners[requestId] = players[randomWords[0] % players.length];
    }
}
"""
SAMPLE_LOOP_V = """
pragma solidity ^0.8.19;
contract Registry {
    address[] borrowers;
    mapping(address => uint) debts;
    function totalDebt() external view returns (uint) {
        uint sum;
        for (uint i = 0; i < borrowers.length; i++) {
            sum += debts[borrowers[i]];
        }
        return sum;
    }
}
"""
SAMPLE_LOOP_S = """
pragma solidity ^0.8.19;
contract RegistrySafe {
    uint constant MAX_BORROWERS = 5000;
    address[] borrowers;
    mapping(address => uint) debts;
    function addBorrower(address who) external {
        require(borrowers.length < MAX_BORROWERS);
        borrowers.push(who);
    }
    function totalDebt() external view returns (uint) {
        uint sum;
        for (uint i = 0; i < borrowers.length; i++) { sum += debts[borrowers[i]]; }
        return sum;
    }
}
"""
SAMPLE_SWAPDL_V = """
pragma solidity ^0.8.19;
contract ArbBot {
    ISwapRouter immutable router;
    function swap(address tokenOut, uint amountIn) external {
        router.exactInputSingle(ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH, tokenOut: tokenOut, fee: 3000, recipient: msg.sender,
            amountIn: amountIn, amountOutMinimum: 0, sqrtPriceLimitX96: 0}));
    }
}
"""
SAMPLE_SWAPDL_S = """
pragma solidity ^0.8.19;
contract ArbBotSafe {
    IUniswapV2Router immutable router;
    function swap(address tokenOut, uint amountIn, uint deadline) external {
        address[] memory p = new address[](2);
        router.swapExactTokensForTokens(amountIn, 1, p, msg.sender, deadline);
    }
}
"""
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

# 全规则测试矩阵: (规则id, 漏洞样例, 安全样例) — 覆盖率不足 selftest 直接失败
# ---- TIMELOCK-ZERO (Term Finance 2026-08 模式) ----
SAMPLE_TIMELOCK_V = """
pragma solidity ^0.8.19;
contract Gov {
    uint public delay = 7 days;
    address admin;
    modifier onlyAdmin { require(msg.sender == admin); _; }
    function setDelay(uint newDelay) external onlyAdmin {
        delay = newDelay;
    }
    function execute() external view returns (bool) { return block.timestamp > delay; }
}
"""
SAMPLE_TIMELOCK_S = """
pragma solidity ^0.8.19;
contract GovSafe {
    uint public delay = 7 days;
    uint public constant MIN_DELAY = 1 days;
    address admin;
    modifier onlyAdmin { require(msg.sender == admin); _; }
    function setDelay(uint newDelay) external onlyAdmin {
        require(newDelay >= MIN_DELAY, "too short");
        delay = newDelay;
    }
}
"""

# ---- CROSSCHAIN-SIG-REPLAY (2026-06 桥 $127M 模式: 缺chainId/nonce) ----
SAMPLE_XCHAIN_V = """
pragma solidity ^0.8.19;
contract BridgeInbox {
    address validator;
    function validateProof(bytes32 msgHash, bytes calldata sig, address dest) external view returns (bool) {
        return ecrerecover(keccak256(abi.encodePacked(msgHash, dest)), sig) == validator;
    }
}
"""
SAMPLE_XCHAIN_S = """
pragma solidity ^0.8.19;
contract BridgeInboxSafe {
    address validator;
    mapping(bytes32 => bool) usedHash;
    function validateProof(bytes32 msgHash, bytes calldata sig, uint256 srcChainId, uint256 seq) external returns (bool) {
        require(block.chainid == srcChainId);
        require(!usedHash[msgHash]);
        usedHash[msgHash] = true;
        return ecrerecover(keccak256(abi.encodePacked(msgHash, srcChainId, seq)), sig) == validator;
    }
}
"""

# ---- HARDCODED-AUTH-SECRET (SquidRouterModule 2026-05 $3.2M 模式) ----
SAMPLE_SECRET_V = """
pragma solidity ^0.8.19;
contract RouterModule {
    function authenticate(bytes memory proof) external pure returns (bool) {
        return keccak256(abi.encodePacked("super-secret-auth-string-2026")) == keccak256(proof);
    }
    function callTarget(bytes32 payload, string memory token) external {
        require(keccak256(abi.encodePacked(token)) == keccak256(abi.encodePacked("module-auth-token-v1")));
        payload;
    }
}
"""
SAMPLE_SECRET_S = """
pragma solidity ^0.8.19;
contract RouterModuleSafe {
    address operator;
    function authenticate(bytes32 payload, bytes calldata sig) external view returns (bool) {
        return ecrerecover(keccak256(abi.encodePacked(payload)), sig) == operator;
    }
}
"""

# ---- LEGACY-LIVE-CONTRACT (Transit Finance 2026-05 $1.88M 模式) ----
SAMPLE_LEGACY_V = """
pragma solidity ^0.8.19;
/// @notice DEPRECATED - use TransitV2 instead
contract TransitRouterLegacy {
    mapping(address => uint) balances;
    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""
SAMPLE_LEGACY_S = """
pragma solidity ^0.8.19;
/// @notice DEPRECATED - use TransitV2 instead
contract TransitRouterLegacySafe {
    bool private stopped;
    function withdraw(uint amount) external {
        require(!stopped, "paused");
        amount;
    }
}
"""

# ---- TAX-BURN-FROM-POOL (FH Token 2026-08-26 $20K 模式) ----
SAMPLE_TAXBURN_V = """
pragma solidity ^0.8.19;
contract FHToken {
    IPancakePair public pair;
    address public dead = 0x000000000000000000000000000000000000dEaD;
    function _transfer(address sender, address recipient, uint256 amount) internal {
        if (isSell(sender)) {
            uint256 burnAmt = IPancakePair(pair).balanceOf(address(this)) * 15 / 100;
            IPancakePair(pair).sync();
        }
        super._transfer(sender, recipient, amount);
    }
}
"""
SAMPLE_TAXBURN_S = """
pragma solidity ^0.8.19;
contract SafeTaxToken {
    address public dead = 0x000000000000000000000000000000000000dEaD;
    function _transfer(address sender, address recipient, uint256 amount) internal {
        uint256 tax = amount * 3 / 100;
        super._transfer(sender, dead, tax);
        super._transfer(sender, recipient, amount - tax);
    }
}
"""

RULE_TESTS = [
    ("COMPOUND-V2-FIRST-DEPOSITOR", SAMPLE_VULN,            SAMPLE_FIXED),
    ("ORACLE-SPOT-PRICE",           SAMPLE_ORACLE_V,        SAMPLE_ORACLE_S),
    ("UNPROTECTED-INITIALIZER",     SAMPLE_INITIALIZER_V,   SAMPLE_INITIALIZER_S),
    ("ARBITRARY-DELEGATECALL",      SAMPLE_DELEGATE_V,      SAMPLE_DELEGATE_S),
    ("UNPROTECTED-MINT",            SAMPLE_MINT_V,          SAMPLE_MINT_S),
    ("REENTRANCY",                  SAMPLE_REENTRANCY_V,    SAMPLE_REENTRANCY_S),
    ("SELFDESTRUCT",                SAMPLE_KILL_V,          SAMPLE_KILL_S),
    ("UNCHECKED-CALL",              SAMPLE_UCALL_V,         SAMPLE_UCALL_S),
    ("INTEGER-OVERFLOW",            SAMPLE_OVERFLOW_V,      SAMPLE_OVERFLOW_S),
    ("PROXY-STORAGE-COLLISION",     SAMPLE_PROXY_V,         SAMPLE_PROXY_S),
    ("TX-ORIGIN",                   SAMPLE_TXORIGIN_V,      SAMPLE_TXORIGIN_S),
    ("MISSING-ZERO-CHECK",          SAMPLE_ZERO_V,          SAMPLE_ZERO_S),
    ("BLOCK-TIMESTAMP",             SAMPLE_TS_V,            SAMPLE_TS_S),
    ("UNCHECKED-TRANSFER",          SAMPLE_UTRANSFER_V,     SAMPLE_UTRANSFER_S),
    ("ERC4626-INFLATION",           SAMPLE_4626,            SAMPLE_4626_SAFE),
    ("SIGNATURE-REPLAY",            SAMPLE_SIG_REPLAY,      SAMPLE_SIG_FIXED),
    ("UNPROTECTED-CALLBACK",        SAMPLE_CALLBACK_VULN,   SAMPLE_CALLBACK_FIXED),
    ("WEAK-RANDOMNESS",             SAMPLE_RAND_V,          SAMPLE_RAND_S),
    ("UNBOUNDED-LOOP-DOS",          SAMPLE_LOOP_V,          SAMPLE_LOOP_S),
    ("MISSING-SWAP-DEADLINE",       SAMPLE_SWAPDL_V,        SAMPLE_SWAPDL_S),
    ("TIMELOCK-ZERO",               SAMPLE_TIMELOCK_V,      SAMPLE_TIMELOCK_S),
    ("CROSSCHAIN-SIG-REPLAY",       SAMPLE_XCHAIN_V,        SAMPLE_XCHAIN_S),
    ("HARDCODED-AUTH-SECRET",       SAMPLE_SECRET_V,        SAMPLE_SECRET_S),
    ("LEGACY-LIVE-CONTRACT",        SAMPLE_LEGACY_V,        SAMPLE_LEGACY_S),
    ("TAX-BURN-FROM-POOL",          SAMPLE_TAXBURN_V,       SAMPLE_TAXBURN_S),
]

def self_test():
    """全规则测试矩阵: 漏洞样例必中 + 安全样例零误报 + 边界输入不崩"""
    tested = {rid for rid, _, _ in RULE_TESTS}
    missing = [r[0] for r in VULN_RULES if r[0] not in tested]
    if missing:
        print(f"❌ 自测矩阵缺规则样例: {missing}")
        raise SystemExit(1)
    fails = []
    for rid, vuln, safe in RULE_TESTS:
        vh = {h["id"] for h in scan_code(vuln)}
        sh = {h["id"] for h in scan_code(safe)}
        if rid not in vh:
            fails.append(f"{rid} 漏洞样例未命中 (实际命中: {sorted(vh) or '无'})")
        if rid in sh:
            fails.append(f"{rid} 安全样例误报 (命中: {sorted(sh)})")
    # 边界: 空输入/非Solidity/超长输入必须安全返回不崩
    for edge, label in (("", "空输入"), ("hello world, not solidity", "非Solidity"),
                        ("x" * 600_000, "600KB超长输入")):
        try:
            scan_code(edge)
        except Exception as e:
            fails.append(f"边界用例[{label}] 异常: {type(e).__name__}: {e}")
    if fails:
        for f in fails:
            print("❌", f)
        raise SystemExit(1)
    print(f"✅ 规则自测通过: 矩阵 {len(RULE_TESTS)}/{len(VULN_RULES)} 条规则全覆盖, "
          f"漏洞样例全命中, 安全样例目标规则 0 误报, 边界输入 3/3 不崩")

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
    p_scan.add_argument("--ai", action="store_true", help="扫完直连 AI 复核命中项")
    p_scan.add_argument("--max", type=int, default=10, help="AI 复核最多审几个项目")
    p_scan.add_argument("--min-sev", choices=["HIGH", "MED", "ALL"], default="HIGH",
                        dest="min_sev", help="AI 复核最低严重级(默认 HIGH)")
    p_scan.set_defaults(func=cmd_scan)

    p_ai = sub.add_parser("ai", help="AI 语义复核 scan 结果")
    p_ai.add_argument("scan_file", nargs="?", default=RESULTS_PATH)
    p_ai.add_argument("--max", type=int, default=10, help="最多审几个项目")
    p_ai.add_argument("--min-sev", choices=["HIGH", "MED", "ALL"], default="HIGH",
                      dest="min_sev", help="只审含该级别以上的项目(默认 HIGH)")
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
