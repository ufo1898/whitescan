#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteScan Monitor — 链上新部署合约实时漏洞监控 v1.5.0
=====================================================
标准库实现（无 pip 依赖，003 VPS / 008 Mac 通吃）。

v1.5.0 新增:
  - 多链并行: 每链独立线程 + 独立 state/hits/统计（--chain mainnet,bsc）
  - BSC 事件驱动: PancakeSwap V2 工厂 PairCreated getLogs 批量扫描
    （BSC 0.75s 出块 + 无免费源码 API，回执逐块模式成本过高 → 事件模式）
  - BYTECODE-FH-TOKEN-SIG: 字节码指纹层。未验证源码的合约不再跳过，
    eth_getCode → 指纹匹配（代币外呼 pair.sync 0xfff6cae9 + gas 全转发 ABI 模式）
    FH/YNP 双样本实锤命中，USDT/UNI/正规 Pair 负对照全零
  - HIGH 命中 → 自动生成 PoC/影响评估报告（reports/{chain}/*.md，
    含攻击向量/影响评估/Foundry PoC 骨架/建议）
  - RPC 指数退避+随机抖动（连续失败不死磕，防公共 RPC 封禁）
  - Webhook SSRF 防护（拒绝内网地址/非 http(s) 协议）
  - 健康上报 monitor_health.json（每链块高/失败连击/扫描统计，看板消费）

数据流:
  [receipts 模式(主网/测试网)] eth_getBlockReceipts → contractAddress 筛选
  [events 模式(BSC)]          eth_getLogs(PairCreated) → token0/token1 新币
  → Blockscout 拉已验证源码 → ws.scan_code() 25 条规则
  → 未验证 → eth_getCode 字节码指纹 → BYTECODE-FH-TOKEN-SIG
  → HIGH/MED 命中告警(stdout + monitor_hits_{chain}.json + webhook)
  → HIGH 额外生成 PoC/影响评估报告 reports/{chain}/{ts}_{addr}.md

用法:
  python3 whitescan_monitor.py                          # 全链并行常驻
  python3 whitescan_monitor.py --chain mainnet,bsc      # 指定链并行
  python3 whitescan_monitor.py --chain bsc --once       # 单链扫一轮
  python3 whitescan_monitor.py --addr 0x..              # 手动深扫（含指纹）
  python3 whitescan_monitor.py selftest                 # 离线自检

环境变量:
  WHITESCAN_ALERT_WEBHOOK  告警 webhook（POST JSON），留空只写文件+stdout
  WHITESCAN_RPC            自定义 RPC，覆盖默认（只覆盖第一优先）
  WHITESCAN_PROXY          出站代理（008 走 QuickQ 时用）

安全边界:
  - 只读链上公开数据，零私钥零签名
  - 源码 >200KB 跳过；每块/批最多处理 30 个新合约
  - 指纹判定要求双特征同中（与 TAX 规则同哲学），单一特征不告警
"""
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import whitescan as ws  # noqa: E402  复用规则引擎

__version__ = "1.5.0"

# ------------------------------------------------------------
# 配置
# ------------------------------------------------------------

PANCAKE_V2_FACTORY = "0xca143ce32fe78f1f7019d7d551a6402fc5350c73"
# PairCreated(address,address,address,uint256) — 与 UniswapV2 同签名
TOPIC_PAIR_CREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"

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
        "mode": "receipts",
        "poll": 12,
    },
    "sepolia": {
        "rpcs": [
            "https://ethereum-sepolia-rpc.publicnode.com",
            "https://1rpc.io/sepolia",
        ],
        "explorer_api": "https://eth-sepolia.blockscout.com/api/v2",
        "explorer_ui": "https://eth-sepolia.blockscout.com",
        "name": "Sepolia 测试网",
        "mode": "receipts",
        "poll": 12,
    },
    "bsc": {
        "rpcs": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
            "https://1rpc.io/bnb",
        ],
        "explorer_api": "https://bnb.blockscout.com/api/v2",
        "explorer_ui": "https://bnb.blockscout.com",
        "name": "BNB Smart Chain",
        "mode": "events",
        "poll": 4,
        "batch": 3000,          # getLogs 单批块数（≈37 分钟）
        "catchup": 600,         # 首启回看块数（≈7.5 分钟）
        "factory": PANCAKE_V2_FACTORY,
        "topic0": TOPIC_PAIR_CREATED,
        "base_tokens": {        # 基础币不入扫描队列（恒为对手盘）
            "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB
            "0x55d398326f99059ff775485246999027b3197955",  # USDT(BSC)
            "0xe9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD
            "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce56",  # CAKE
            "0x8ac76a51cc950d9822d68b83fe1ad97b28cdcf4e",  # USDC(BSC)
            "0x2170ed0880ac9a755fd29b2688956bd959f933f8",  # ETH(BSC)
        },
    },
}

# RPC 必须带浏览器 UA（裸 whitescan UA 会被 403）
HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Content-Type": "application/json",
}

MAX_SOURCE_BYTES = 200 * 1024   # 源码上限
MAX_CONTRACTS_PER_BLOCK = 30    # 每块/批新合约处理上限
MAX_CATCHUP_BLOCKS = 10         # receipts 模式单轮最多追块数
DEFAULT_POLL = 12               # 链未配 poll 时的兜底轮询间隔（秒）
ALERT_SEVERITIES = {"HIGH", "MED"}  # 触发告警的等级；LOW 只入库不告警

STATE_PATH = os.path.join(SCRIPT_DIR, "monitor_state_{chain}.json")
HITS_PATH = os.path.join(SCRIPT_DIR, "monitor_hits_{chain}.json")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports", "{chain}")
HEALTH_PATH = os.path.join(SCRIPT_DIR, "monitor_health.json")
HEALTH_LOCK = threading.Lock()

# ------------------------------------------------------------
# PoC/影响评估模板（HIGH 规则 → 攻击向量 + Foundry 骨架）
# ------------------------------------------------------------

POC_TEMPLATES = {
    "COMPOUND-V2-FIRST-DEPOSITOR": {
        "attack": "首存者 supply 1 wei 成为唯一份额持有人 → 直接向金库捐赠底层代币抬升 "
                  "exchangeRate → 后入者按虚高汇率 mint 只获得趋零份额 → 首存者 redeem 抽走全部"
                  "（含后入者本金）。已在本仓库 references/first_depositor_poc.sol 实证。",
        "impact": "后入者本金 100% 可被抽干，受损金额=其后全部存款",
        "exploit": "无需权限，仅需一笔前置交易+一笔捐赠，成本低",
        "poc": """// Foundry PoC 骨架 — COMPOUND-V2-FIRST-DEPOSITOR
function test_first_depositor_drain() public {
    // 1. attacker 首存 1 wei（此时 supply==0 分支返回 initialExchangeRate）
    vm.prank(attacker); cToken.mint(1);
    // 2. 直接捐赠抬升汇率（绕过 mint，不产生份额）
    underlying.transfer(address(cToken), 100 ether);
    // 3. victim 正常存入
    deal(address(underlying), victim, 10 ether);
    vm.prank(victim); cToken.mint(10 ether);
    // 4. attacker redeem 全部 → 抽走 victim 本金
    vm.prank(attacker); cToken.redeem(cToken.balanceOf(attacker));
    assertLt(underlying.balanceOf(victim) + cToken.balanceOf(victim), 1e6); // victim 被抽干
}""",
    },
    "ORACLE-SPOT-PRICE": {
        "attack": "协议以池子现货价（balanceOf/getReserves）作价 → 单块内闪电贷拉偏池价 "
                  "→ 按虚假价格借贷/清算/铸币 → 同块归还闪电贷",
        "impact": "金库可被以接近零成本借空/清算套利，损失上限=可借资产总量",
        "exploit": "需要一笔闪电贷本金（可循环），同一交易内完成，无尾款风险",
        "poc": """// Foundry PoC 骨架 — ORACLE-SPOT-PRICE
function test_spot_price_manipulation() public {
    deal(address(token), address(this), 1_000_000 ether);
    token.transfer(address(pair), 1_000_000 ether); pair.sync(); // 拉低池价 10000 倍
    uint before = vault.collateralPrice();
    vault.borrow(1_000_000 ether);            // 按虚假抵押价借出
    token.transfer(address(pair), 0); pair.sync(); // 恢复价（本例简化）
    assertGt(borrowed, fairBorrowLimit * 100); // 借出远超公允值
}""",
    },
    "UNPROTECTED-INITIALIZER": {
        "attack": "initialize 无 onlyOwner/initializer/重入锁守卫 → 任何人抢先把 "
                  "owner/关键参数设为自己 → 完全接管合约",
        "impact": "合约所有权被接管，全部资金/升级权限沦陷",
        "exploit": "一笔交易即可，窗口=部署后到合法 initialize 之前（抢跑可覆盖后初始化）",
        "poc": """// Foundry PoC 骨架 — UNPROTECTED-INITIALIZER
function test_takeover_via_initialize() public {
    vm.prank(attacker); target.initialize(attacker, 1); // 无守卫直接初始化
    assertEq(target.owner(), attacker);        // 接管成功
    vm.prank(attacker); target.withdrawAll();  // 直接提走资金
}""",
    },
    "ARBITRARY-DELEGATECALL": {
        "attack": "delegatecall 目标来自用户输入/可改配置 → 指向攻击者合约 → 在本合约"
                  "上下文任意执行（改 owner/自毁/转走资金）",
        "impact": "合约完全沦陷（存储上下文被任意改写），等价于私钥泄露",
        "exploit": "一笔交易，无需特殊窗口",
        "poc": """// Foundry PoC 骨架 — ARBITRARY-DELEGATECALL
function test_hijack_via_delegatecall() public {
    Malicious m = new Malicious();           // 其 fallback 里写 owner=attacker
    bytes memory data = abi.encodeWithSelector(m.doPwn.selector);
    (bool ok,) = address(target).call(abi.encodeWithSelector(target.exec.selector,
                                                             address(m), data));
    assertTrue(ok);
    assertEq(target.owner(), attacker);       // 存储被改写
}""",
    },
    "UNPROTECTED-MINT": {
        "attack": "mint 函数无 any 权限控制 → 任何人无限增发 → 直接稀释/砸盘",
        "impact": "代币总供应失控，持有者资产被无限稀释",
        "exploit": "一笔交易，任何人可触发",
        "poc": """// Foundry PoC 骨架 — UNPROTECTED-MINT
function test_anyone_can_mint() public {
    vm.prank(attacker); token.mint(attacker, 1e30);
    assertGt(token.totalSupply(), 1e29);      // 无权限增发成功
}""",
    },
    "ERC4626-INFLATION": {
        "attack": "空金库场景: 攻击者先存 1 wei share → 直捐资产抬升 share 价格 → "
                  "受害者存入只获得趋零 share → 攻击者赎回抽干（first-depositor 的 4626 变体）",
        "impact": "后入存款人本金可被接近全额抽走",
        "exploit": "需抢先于第一位真实存款人，否则金库已有防御（虚拟份额/死份额）",
        "poc": """// Foundry PoC 骨架 — ERC4626-INFLATION
function test_4626_inflation() public {
    vm.prank(attacker); vault.deposit(1, attacker);
    asset.transfer(address(vault), 100 ether);   // 直捐
    deal(address(asset), victim, 10 ether);
    vm.startPrank(victim); asset.approve(address(vault), 10 ether);
    vault.deposit(10 ether, victim); vm.stopPrank();
    uint shares = vault.balanceOf(victim);
    assertLt(shares, 1e3);                        // 只拿到尘埃份额
}""",
    },
    "SIGNATURE-REPLAY": {
        "attack": "链上消费签名无 nonce/deadline/chainId 绑定 → 同一签名可被重复提交消费",
        "impact": "同一授权被执行多次：重复提款/重复转账/重复投票",
        "exploit": "截获一次合法签名即可反复重放",
        "poc": """// Foundry PoC 骨架 — SIGNATURE-REPLAY
function test_sig_replay() public {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, permitDigest);
    token.permit(user, spender, amt, deadline, v, r, s);  // 第一次合法
    token.permit(user, spender, amt, deadline, v, r, s);  // 第二次应 revert
    // 未 revert 且授权再次生效 = 签名重放漏洞成立
}""",
    },
    "UNPROTECTED-CALLBACK": {
        "attack": "对外部回调（uniswapV3SwapCallback/onFlashLoan/…）不校验 msg.sender "
                  "是否为合法发起方 → 攻击者伪装回调携带任意参数骗取转账/授权",
        "impact": "合约资金可被以伪造回调形式直接骗走",
        "exploit": "一笔交易直接调用回调接口",
        "poc": """// Foundry PoC 骨架 — UNPROTECTED-CALLBACK
function test_fake_callback_drain() public {
    bytes memory data = abi.encode(address(token), int256(-1000 ether), attacker);
    vm.prank(attacker);
    target.uniswapV3SwapCallback(int256(-1000 ether), 0, data); // 伪造回调
    assertGt(token.balanceOf(attacker), 0);   // 未校验 sender 直接付款
}""",
    },
    "TIMELOCK-ZERO": {
        "attack": "timelock delay=0 → 管理员提案可即时执行 → 无缓冲期，恶意/被盗私钥"
                  "即时抽资，用户无撤离窗口",
        "impact": "治理保护形同虚设，管理员权限等价于即时全额资金风险",
        "exploit": "需要管理员权限（私钥被盗/恶意后端即可）",
        "poc": """// Foundry PoC 骨架 — TIMELOCK-ZERO
function test_timelock_instant_execute() public {
    vm.prank(admin); timelock.schedule(address(vault), 0, abi.encode(
        vault.withdrawAll.selector), 0);      // delay=0
    vm.prank(admin); timelock.execute(address(vault), 0, abi.encode(
        vault.withdrawAll.selector), 0);      // 同块立即执行成功 = 无延时
}""",
    },
    "CROSSCHAIN-SIG-REPLAY": {
        "attack": "跨链消息签名未绑定目标链 chainId/目标合约 → A 链合法签名可在 B 链"
                  "同合约重放消费",
        "impact": "跨链资产被双花：同一笔提款/铸造在多条链重复执行",
        "exploit": "拿到 A 链签名后提交到 B 链实例",
        "poc": """// Foundry PoC 骨架 — CROSSCHAIN-SIG-REPLAY
function test_crosschain_replay() public {
    bytes memory sig = signOnChainA();        // 桥消息: mint 100 to attacker
    bridgeB.submitMessage(msgHash, sig);      // B 链重放
    assertEq(tokenB.balanceOf(attacker), 100 ether); // 双花成立
}""",
    },
    "TAX-BURN-FROM-POOL": {
        "attack": "FH Token 家族实锤模式（主网 2026-08 案例）: 合约特权函数把池内代币"
                  "转出/销毁后主动调用 pair.sync() → K 值被人为改变 → 用户按虚假储备价"
                  "卖出遭遇极端滑点 → 池子被抽干。75 笔 Sync vs 50 笔 Swap 为特征。",
        "impact": "LP 与持币人资金全损（案例: 单池净流出 19,999.87 USDT）",
        "exploit": "特权函数由部署者随时触发，买入即靶",
        "poc": """// Foundry PoC 骨架 — TAX-BURN-FROM-POOL
function test_drain_pool_via_sync() public {
    deal(address(token), address(pair), 20_000 ether); // 模拟池内已有币
    vm.prank(deployer); token.burnFromPool(10_000 ether); // 池内币被烧/转走
    vm.prank(deployer); token.callSync();                  // 主动 sync 伪造 K
    (uint r0,,) = pair.getReserves();
    assertLt(r0, 10_000 ether);               // 储备被人为改变
    // 用户此时卖出 → 虚假报价 → 极端滑点
}""",
    },
    "BYTECODE-FH-TOKEN-SIG": {
        "attack": "字节码指纹匹配 FH Token 家族: 代币合约存在外部调用 pair.sync()"
                  "（0xfff6cae9）且带 gas 全转发 ABI 编码模式。正常代币/正规 Pair 均无"
                  "此模式（负对照: USDT/UNI/USDT-WETH Pair 全零命中）。",
        "impact": "同 TAX-BURN-FROM-POOL: LP 资金可被部署者通过池内操作抽干",
        "exploit": "字节码级实锤，无需源码即可定性；买入即靶",
        "poc": """// 黑盒验证路径（未验证源码 → 字节码指纹命中）
// 1. 观察法: 盯 pair 的 Sync 事件频率（远高于 Swap 即异常）
// 2. Foundry fork 验证:
function test_fingerprint_family() public {
    // fork BSC, 以目标代币建池
    vm.prank(deployer); target.triggerPoolOp();   // 特权函数
    vm.expectEmit(true, true, true, true, address(pair));
    emit Sync(0, 0);                              // sync 被外部驱动
    // 池子 reserve 被非 swap 交易改变 = 家族行为确认
}""",
    },
}

# ------------------------------------------------------------
# HTTP 底座（代理 + UA + 超时 + SSRF 防护）
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


_PRIVATE_HOST_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^0\."),
    re.compile(r"^\[?::1\]?$"),
    re.compile(r"^\[?::ffff:127\.", re.I),  # IPv4-mapped IPv6
    re.compile(r"^f[cd][0-9a-f]{2}:", re.I),  # fc00::/7 fe80::/10
    re.compile(r"^localhost$", re.I),
]


def ssrf_check_url(url):
    """webhook 目标校验: 只允许 http(s) + 拒绝内网/环回地址。返回 (ok, err)"""
    m = re.match(r"^(https?)://(\[[0-9a-fA-F:.]+\]|[^/:?#]+)", url or "", re.I)
    if not m:
        return False, "仅允许 http/https 协议"
    host = m.group(2)
    for rx in _PRIVATE_HOST_PATTERNS:
        if rx.search(host):
            return False, f"内网地址不允许: {host}"
    return True, ""


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
# RPC 层（故障转移 + 指数退避 + 抖动）
# ------------------------------------------------------------

def _rpc_base(chain_cfg):
    """当前应使用的 RPC 列表（WHITESCAN_RPC 优先）"""
    custom = os.environ.get("WHITESCAN_RPC", "").strip()
    return [custom] if custom else chain_cfg["rpcs"]


def rpc_call(chain_cfg, method, params, ctx=None, timeout=12):
    """JSON-RPC 调用，失败自动换下一个 RPC 端点。ctx 持有 rpc_idx/fail_streak"""
    if ctx is None:
        ctx = {"rpc_idx": 0}
    rpcs = _rpc_base(chain_cfg)
    last_err = None
    for i in range(len(rpcs)):
        url = rpcs[(ctx.get("rpc_idx", 0) + i) % len(rpcs)]
        try:
            d = http_json(url, {"jsonrpc": "2.0", "method": method,
                                "params": params, "id": 1}, timeout=timeout)
            if "error" in d:
                raise RuntimeError(str(d["error"])[:120])
            ctx["rpc_idx"] = (ctx.get("rpc_idx", 0) + i) % len(rpcs)
            ctx["fail_streak"] = 0
            return d["result"]
        except Exception as e:  # noqa: BLE001
            last_err = e
    if ctx is not None:
        ctx["fail_streak"] = ctx.get("fail_streak", 0) + 1
    raise RuntimeError(f"全部RPC失败: {last_err}")


def backoff_delay(streak, base=2.0, cap=120.0):
    """指数退避 + 30% 随机抖动。streak=连续失败次数"""
    if streak <= 0:
        return 0.0
    d = min(base * (2 ** min(streak - 1, 6)), cap)
    return d * (1.0 + random.random() * 0.3)


# ------------------------------------------------------------
# 字节码指纹层（BYTECODE-FH-TOKEN-SIG）
# ------------------------------------------------------------

# 特征 A: 代币合约外部 CALL pair.sync() —— AND 掩码(addr)+PUSH4 selector
# 特征 B: sync 调用的完整 ABI 编码片段（PUSH4+gas 全转发模式）
# 判定: A 且 B 同中 → HIGH。负对照(USDT/UNI/正规Pair/正常ERC20)全零。
BYTECODE_FH_PATTERNS = {
    "sync_call": "1663fff6cae9",
    "sync_abi": "63fff6cae96040518163ffffffff1660e01b",
}


def bytecode_fingerprint(code_hex):
    """未验证源码合约的字节码指纹。返回 hits 列表（FH 家族 → HIGH）"""
    c = (code_hex or "").lower()
    if c.startswith("0x"):
        c = c[2:]
    if len(c) < 200:
        return []
    a = BYTECODE_FH_PATTERNS["sync_call"] in c
    b = BYTECODE_FH_PATTERNS["sync_abi"] in c
    if a and b:
        return [{"id": "BYTECODE-FH-TOKEN-SIG", "sev": "HIGH",
                 "desc": "字节码指纹: 代币外呼 pair.sync() + gas 全转发模式 = FH Token 家族"
                         "（操纵K值/抽池，主网已实锤单池流出 2 万 USDT）",
                 "why": "bytecode contains token.call(pair.sync 0xfff6cae9) with "
                        "gas-forward ABI pattern; 双特征同中，正常代币与正规 Pair 均无"}]
    return []


# ------------------------------------------------------------
# 区块/事件 → 新合约提取
# ------------------------------------------------------------

def latest_block(chain_cfg, ctx):
    n = rpc_call(chain_cfg, "eth_blockNumber", [], ctx)
    return int(n, 16)


def block_receipts(chain_cfg, ctx, height):
    """整块回执一把抓（覆盖 to=null 直接创建 + CREATE2 工厂部署）"""
    hexh = hex(height)
    try:
        receipts = rpc_call(chain_cfg, "eth_getBlockReceipts", [hexh], ctx)
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


def fetch_pair_created_logs(chain_cfg, ctx, from_b, to_b):
    """BSC 事件模式: getLogs 拉 PancakeV2 工厂 PairCreated"""
    flt = {
        "fromBlock": hex(from_b),
        "toBlock": hex(to_b),
        "address": chain_cfg["factory"],
        "topics": [chain_cfg["topic0"]],
    }
    logs = rpc_call(chain_cfg, "eth_getLogs", [flt], ctx, timeout=25)
    return logs if isinstance(logs, list) else []


def parse_pair_created(log):
    """PairCreated log → {token0, token1, pair, tx, block}。解析失败返回 None"""
    topics = log.get("topics") or []
    if len(topics) < 3:
        return None
    data = (log.get("data") or "0x")[2:]
    pair = ("0x" + data[:64][-40:].lower()) if len(data) >= 64 else ""
    try:
        block = int(log.get("blockNumber") or "0x0", 16)
    except ValueError:
        block = 0
    return {
        "token0": ("0x" + topics[1][-40:]).lower(),
        "token1": ("0x" + topics[2][-40:]).lower(),
        "pair": pair,
        "tx": log.get("transactionHash", ""),
        "block": block,
    }


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


def eth_get_code(chain_cfg, ctx, address):
    try:
        return rpc_call(chain_cfg, "eth_getCode", [address, "latest"], ctx) or "0x"
    except Exception:  # noqa: BLE001
        return "0x"


# ------------------------------------------------------------
# 扫描 + 报告 + 告警
# ------------------------------------------------------------

def scan_source(source_code):
    """跑 whitescan.py 全部规则（动态载入，返回 hits；超大源码直接跳过）"""
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


def gen_report(chain_key, chain_cfg, rec):
    """HIGH 命中 → 自动生成 PoC/影响评估报告。返回报告路径，无 HIGH 返回 None"""
    high_hits = [h for h in rec["hits"] if h.get("sev") == "HIGH"]
    if not high_hits:
        return None
    rdir = REPORTS_DIR.format(chain=chain_key)
    try:
        os.makedirs(rdir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime(rec["ts"]))
        path = os.path.join(rdir, f"{ts}_{rec['address'][2:10]}.md")
        lines = [
            "# WhiteScan PoC / 影响评估报告",
            "",
            f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rec['ts']))}",
            f"- 合约: {rec['contract_name']} `{rec['address']}`",
            f"- 链: {rec['chain_name']}（块 #{rec['block']}）",
            f"- 创建交易: {rec['tx']}",
            f"- 扫描来源: {'已验证源码' if rec.get('scan_mode') == 'source' else '字节码指纹（未验证源码）'}",
            f"- 浏览器: {rec['explorer_ui']}/address/{rec['address']}",
            "",
            "## 命中规则（HIGH）",
            "",
            "| 等级 | 规则 | 说明 |",
            "|------|------|------|",
        ]
        for h in rec["hits"]:
            lines.append(f"| {h['sev']} | `{h['id']}` | {h['desc']} |")
        lines += ["", "## 攻击向量与影响评估", ""]
        for h in high_hits:
            t = POC_TEMPLATES.get(h["id"], {})
            lines.append(f"### {h['id']}")
            if t.get("attack"):
                lines += ["", f"**攻击路径**: {t['attack']}"]
            if t.get("impact"):
                lines += ["", f"**影响**: {t['impact']}"]
            if t.get("exploit"):
                lines += ["", f"**可利用性**: {t['exploit']}"]
            if h.get("why"):
                lines += ["", f"**本合约证据**: {h['why']}"]
            if t.get("poc"):
                lines += ["", "**PoC 骨架（Foundry）**:", "", "```solidity",
                          t["poc"], "```", ""]
        lines += [
            "## 建议",
            "",
            "1. 静态扫描初筛结论，交互前务必人工复核（尤其 PoC 骨架中的关键假设）",
            "2. 字节码指纹命中的合约默认按毒币处理：不买、不授权、不提供流动性",
            "3. 已验证源码的合约可将本报告骨架直接 fork 到 Foundry 实测验证",
            "",
            "---",
            f"*WhiteScan Monitor v{__version__} 自动生成 · 只读链上公开数据 · 零私钥*",
            "",
        ]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
    except Exception:  # noqa: BLE001  报告失败不拖垮告警
        return None


def send_webhook(message):
    """POST JSON 到 WHITESCAN_ALERT_WEBHOOK（Telegram sendMessage 兼容格式）。
    带 SSRF 防护: 只允许 http(s) 公网地址。"""
    url = os.environ.get("WHITESCAN_ALERT_WEBHOOK", "").strip()
    if not url:
        return False
    ok, err = ssrf_check_url(url)
    if not ok:
        print(f"  ⚠️ webhook 拒绝发送: {err}", flush=True)
        return False
    try:
        http_json(url, {"text": message, "chat_id": ""}, timeout=10)
        return True
    except Exception:  # 告警通道故障不拖垮主循环
        return False


def fmt_alert(rec):
    """告警文本：简洁人话，一条一个合约"""
    chain_name = rec["chain_name"]
    mode_tag = "字节码指纹" if rec.get("scan_mode") == "bytecode" else "源码"
    lines = [f"🚨 WhiteScan 链上告警 [{chain_name} #{rec['block']}]",
             f"合约: {rec['address']} ({rec['contract_name']}) [{mode_tag}]",
             f"创建交易: {rec['tx']}"]
    for h in rec["hits"]:
        lines.append(f"[{h['sev']}] {h['id']}: {h['desc'][:80]}")
    lines.append(f"源码: {rec['explorer_ui']}/address/{rec['address']}")
    if rec.get("report"):
        lines.append(f"📄 PoC报告: {rec['report']}")
    return "\n".join(lines)


def chain_paths(chain_key):
    """按链解析 state/hits 文件路径"""
    return (STATE_PATH.format(chain=chain_key), HITS_PATH.format(chain=chain_key))


def process_contract(chain_cfg, ctx, chain_key, item, height):
    """单合约全流程：源码→扫描 / 未验证→字节码指纹。返回 record 或 None"""
    address = item["address"]
    name, src = fetch_verified_source(chain_cfg["explorer_api"], address)
    hits, scan_mode = [], None
    if name is not None:
        hits = scan_source(src)
        scan_mode = "source"
    else:
        # v1.5.0: 未验证源码不再跳过 → 字节码指纹
        code = eth_get_code(chain_cfg, ctx, address)
        hits = bytecode_fingerprint(code)
        scan_mode = "bytecode"
    if not hits:
        return None
    rec = {
        "ts": int(time.time()),
        "chain": chain_key, "chain_name": chain_cfg["name"],
        "block": height, "address": address, "tx": item["tx"],
        "contract_name": name or "Unverified",
        "hits": [{"sev": h["sev"], "id": h["id"], "desc": h["desc"],
                  "why": h.get("why", "")} for h in hits],
        "explorer_ui": chain_cfg["explorer_ui"],
        "scan_mode": scan_mode,
        "alerted": any(h["sev"] in ALERT_SEVERITIES for h in hits),
    }
    if rec["alerted"]:
        rec["report"] = gen_report(chain_key, chain_cfg, rec)
    return rec


def handle_record(rec, hits_path, ctx):
    """告警落盘 + webhook + 统计"""
    if not rec:
        return 0
    append_hit(rec, hits_path)
    ctx["stats"]["scanned"] = ctx["stats"].get("scanned", 0) + 1
    if rec["alerted"]:
        ctx["stats"]["alerts"] = ctx["stats"].get("alerts", 0) + 1
        if any(h["sev"] == "HIGH" for h in rec["hits"]):
            ctx["stats"]["high"] = ctx["stats"].get("high", 0) + 1
        msg = fmt_alert(rec)
        print(msg, flush=True)
        send_webhook(msg)
        return 1
    return 0


# ------------------------------------------------------------
# 每链主循环（receipts / events 两种模式）
# ------------------------------------------------------------

def scan_block(chain_cfg, ctx, height, seen, hits_path, chain_key):
    """receipts 模式: 扫一个块的新合约。返回 (处理数, 告警数)"""
    receipts = block_receipts(chain_cfg, ctx, height)
    creations = extract_creations(receipts)
    if not creations:
        return 0, 0
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
            rec = process_contract(chain_cfg, ctx, chain_key, item, height)
            n_alert += handle_record(rec, hits_path, ctx)
        except Exception as e:  # noqa: BLE001  单合约故障不拖垮整块
            print(f"  ⚠️ {item['address'][:12]} 处理失败: {str(e)[:80]}", flush=True)
        time.sleep(0.3)  # 对 Blockscout 温柔点（免费公共实例）
    return n_scanned, n_alert


def scan_events_range(chain_cfg, ctx, chain_key, from_b, to_b, seen, hits_path):
    """events 模式(BSC): getLogs 批量拉 PairCreated → 新币 → 指纹/源码扫描"""
    logs = fetch_pair_created_logs(chain_cfg, ctx, from_b, to_b)
    n_tok, n_alert = 0, 0
    base = chain_cfg.get("base_tokens", set())
    for log in logs:
        ev = parse_pair_created(log)
        if not ev:
            continue
        for tok in (ev["token0"], ev["token1"]):
            if not tok or tok == "0x0000000000000000000000000000000000000000":
                continue
            if tok in base or tok in seen:
                continue
            if n_tok >= MAX_CONTRACTS_PER_BLOCK:
                return n_tok, n_alert  # 本批到上限，块进度仍推进（seen 已记的不丢）
            seen.add(tok)
            n_tok += 1
            try:
                rec = process_contract(chain_cfg, ctx, chain_key,
                                       {"address": tok, "tx": ev["tx"], "from": ""},
                                       ev["block"])
                n_alert += handle_record(rec, hits_path, ctx)
            except Exception as e:  # noqa: BLE001
                print(f"  ⚠️ [BSC] {tok[:12]} 处理失败: {str(e)[:80]}", flush=True)
            time.sleep(0.2)
    return n_tok, n_alert


def write_health(chain_key, ctx, last_height):
    """健康上报（看板消费）: 块高/失败连击/统计/当前 RPC"""
    try:
        with HEALTH_LOCK:
            h = load_json(HEALTH_PATH, {})
            rpcs = _rpc_base(CHAINS[chain_key])
            h[chain_key] = {
                "name": CHAINS[chain_key]["name"],
                "mode": CHAINS[chain_key]["mode"],
                "last_block": last_height,
                "ts": int(time.time()),
                "fail_streak": ctx.get("fail_streak", 0),
                "rpc": rpcs[ctx.get("rpc_idx", 0) % len(rpcs)],
                "stats": dict(ctx.get("stats", {})),
                "seen": len(ctx.get("seen", [])),
            }
            save_json(HEALTH_PATH, h)
    except Exception:  # noqa: BLE001
        pass


def run_chain(chain_key, once=False):
    """单链常驻循环。receipts(主网/测试网) 或 events(BSC) 模式"""
    chain_cfg = CHAINS[chain_key]
    state_path, hits_path = chain_paths(chain_key)
    state = load_json(state_path, {})
    ctx = {"rpc_idx": 0, "fail_streak": 0,
           "stats": {"scanned": 0, "alerts": 0, "high": 0}}
    seen = set(state.get("seen", []))
    ctx["seen"] = seen
    last_height = state.get("last_height", 0)
    mode = chain_cfg["mode"]

    print(f"🐾 WhiteScan Monitor v{__version__} 启动 [{chain_cfg['name']}|{mode}]"
          f" 规则数={len(ws.VULN_RULES)}+指纹层", flush=True)

    while True:
        try:
            tip = latest_block(chain_cfg, ctx)
            if mode == "events":
                if last_height == 0:
                    last_height = max(tip - chain_cfg.get("catchup", 600), 0)
                start = last_height + 1
                if start <= tip:
                    end = min(start + chain_cfg.get("batch", 3000) - 1, tip)
                    nt, na = scan_events_range(chain_cfg, ctx, chain_key,
                                               start, end, seen, hits_path)
                    last_height = end
                    if nt:
                        print(f"  🔎 块#{start}-{end}: 新币 {nt}, 告警 {na}", flush=True)
            else:
                if last_height == 0:
                    last_height = tip - 1  # 首启从最新块开始，不回溯历史
                if tip > last_height:
                    start = max(last_height + 1, tip - MAX_CATCHUP_BLOCKS)
                    for h in range(start, tip + 1):
                        n, a = scan_block(chain_cfg, ctx, h, seen, hits_path, chain_key)
                        last_height = h
                        if n:
                            print(f"  📦 块#{h}: 新合约 {n} 个, 告警 {a}", flush=True)
            save_json(state_path, {
                "last_height": last_height,
                "seen": list(seen)[-2000:],  # 有界，防无限膨胀
                "ts": int(time.time()),
            })
            write_health(chain_key, ctx, last_height)
        except Exception as e:  # noqa: BLE001  主循环永不退出
            streak = ctx.get("fail_streak", 0) + 1
            ctx["fail_streak"] = streak
            d = backoff_delay(streak)
            print(f"  ⚠️ [{chain_cfg['name']}] 轮询异常(连续{streak}次): "
                  f"{str(e)[:90]} → 退避 {d:.0f}s", flush=True)
            time.sleep(d)
            continue
        if once:
            print(f"✅ [{chain_cfg['name']}] --once 完成", flush=True)
            return
        time.sleep(chain_cfg.get("poll", DEFAULT_POLL))


# ------------------------------------------------------------
# 手动单合约深扫
# ------------------------------------------------------------

def scan_single_address(chain_key, address):
    chain_cfg = CHAINS[chain_key]
    ctx = {"rpc_idx": 0, "fail_streak": 0, "stats": {}}
    name, src = fetch_verified_source(chain_cfg["explorer_api"], address)
    if name is not None:
        hits = scan_source(src)
        print(f"合约 {name} @ {address} | 源码 {len(src or '')}B | 命中 {len(hits)}", flush=True)
    else:
        code = eth_get_code(chain_cfg, ctx, address)
        hits = bytecode_fingerprint(code)
        print(f"合约 {address} | 无已验证源码 | 字节码 {len(code) // 2}B | 指纹命中 {len(hits)}",
              flush=True)
    for h in hits:
        print(f"  [{h['sev']}] {h['id']}: {h['desc']}")
    if not hits:
        print("✅ 未命中规则（不代表无漏洞，静态引擎覆盖有限）", flush=True)
    return hits


# ------------------------------------------------------------
# selftest（离线，fixture 驱动）
# ------------------------------------------------------------

def selftest():
    """离线自检：提取/扫描/指纹/报告/退避/SSRF/事件解析 全链路 mock 验证"""
    ok = []

    # 1) extract_creations：直接创建 + CREATE2 + 空地址过滤 + 去重
    fake_receipts = [
        {"transactionHash": "0xaa", "from": "0xf1", "contractAddress": "0xAAA1"},
        {"transactionHash": "0xbb", "from": "0xf2",
         "contractAddress": "0x0000000000000000000000000000000000000000"},
        {"transactionHash": "0xcc", "from": "0xf3", "contractAddress": None},
        {"transactionHash": "0xaa", "from": "0xf1", "contractAddress": "0xAAA1"},
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
    assert scan_source("not solidity at all {{{") is not None
    assert scan_source("x" * (MAX_SOURCE_BYTES + 1)) == []
    ok.append("规则引擎扫描")

    # 3) 字节码指纹: FH 真实特征双中 → HIGH；负对照全零
    fh_frag = ("6080604052" + "348015610010575f80fd5b50"  # 常规头部
               + "73ffffffffffffffffffffffffffffffffffffffff"
               + "1663fff6cae96040518163ffffffff1660e01b81526004016020604051808303816000875af1"
               + "1580156100d0573d5f803e3d5ffd5b505050" + "5f" * 20)  # 尾部填充
    fh_hits = bytecode_fingerprint("0x" + fh_frag)
    assert len(fh_hits) == 1 and fh_hits[0]["id"] == "BYTECODE-FH-TOKEN-SIG" \
        and fh_hits[0]["sev"] == "HIGH", f"FH指纹未命中: {fh_hits}"
    # 负对照1: 正规 Pair 自己实现 sync（裸选择器出现、无外呼模式）
    pair_like = "6080604052" + "63fff6cae9" + "5f" * 60
    assert bytecode_fingerprint("0x" + pair_like) == [], "正规Pair误报!"
    # 负对照2: 只有特征A无特征B
    a_only = "1663fff6cae9" + "5f" * 60
    assert bytecode_fingerprint("0x" + a_only) == [], "单特征误报!"
    # 负对照3: 空码/极短码
    assert bytecode_fingerprint("0x") == [] and bytecode_fingerprint("0x6080") == []
    ok.append("字节码指纹(正/负对照)")

    # 4) 报告生成: HIGH → 落盘含模板内容；无 HIGH → None
    rec = {"ts": 1756400000, "chain_name": "以太坊主网", "block": 123,
           "address": "0xabc0000000000000000000000000000000000abc",
           "tx": "0xtx", "contract_name": "EvilToken", "explorer_ui": "https://x",
           "scan_mode": "source",
           "hits": [{"sev": "HIGH", "id": "UNPROTECTED-MINT",
                     "desc": "mint 无权限控制", "why": "证据abc"}]}
    global REPORTS_DIR
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        old_rd = REPORTS_DIR
        REPORTS_DIR = os.path.join(td, "{chain}")
        try:
            p = gen_report("mainnet", CHAINS["mainnet"], rec)
            assert p and os.path.exists(p), f"报告未生成: {p}"
            body = open(p, encoding="utf-8").read()
            assert "0xabc" in body and "UNPROTECTED-MINT" in body \
                and "攻击路径" in body and "PoC 骨架" in body and "vm.prank" in body
            med_only = dict(rec, hits=[{"sev": "MED", "id": "REENTRANCY",
                                        "desc": "d", "why": ""}])
            assert gen_report("mainnet", CHAINS["mainnet"], med_only) is None
        finally:
            REPORTS_DIR = old_rd
    ok.append("PoC报告生成")

    # 5) SSRF 防护
    assert ssrf_check_url("https://hooks.example.com/t")[0] is True
    for bad in ["http://127.0.0.1/x", "http://192.168.1.1/hook", "http://10.0.0.1/x",
                "http://172.16.0.1/x", "file:///etc/passwd", "ftp://a.com/x",
                "http://[::1]/x", "http://localhost/x"]:
        assert ssrf_check_url(bad)[0] is False, f"SSRF未拦截: {bad}"
    ok.append("SSRF防护")

    # 6) 退避: 单调区域内有界 + jitter 范围合理
    ds = [backoff_delay(s) for s in range(1, 9)]
    assert all(0 < d <= 120 * 1.3 for d in ds), f"退避越界: {ds}"
    assert max(ds) > 100, f"退避未达cap: {ds}"
    assert backoff_delay(0) == 0
    ok.append("退避+抖动")

    # 7) PairCreated 解析: token0/token1/pair/tx
    ev = parse_pair_created({
        "topics": [TOPIC_PAIR_CREATED,
                   "0x000000000000000000000000" + "aa" * 20,
                   "0x000000000000000000000000" + "bb" * 20],
        "data": "0x" + "00" * 12 + "cc" * 20 + "0000...03e8",
        "transactionHash": "0xth", "blockNumber": hex(118623540),
    })
    assert ev["token0"] == "0x" + "aa" * 20 and ev["token1"] == "0x" + "bb" * 20 \
        and ev["pair"] == "0x" + "cc" * 20 and ev["block"] == 118623540, f"解析错: {ev}"
    assert parse_pair_created({"topics": ["0x01"]}) is None  # topics不足
    ok.append("PairCreated解析")

    # 8) BSC 白名单排除
    base = CHAINS["bsc"]["base_tokens"]
    assert "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c" in base  # WBNB
    ok.append("BSC基础币白名单")

    # 9) 告警格式：含地址/等级/报告路径/模式标签
    rec2 = {"chain_name": "以太坊主网", "block": 123, "address": "0xabc",
            "contract_name": "T", "tx": "0xt", "explorer_ui": "https://x",
            "scan_mode": "bytecode", "report": "/root/whitescan/reports/mainnet/a.md",
            "hits": [{"sev": "HIGH", "id": "BYTECODE-FH-TOKEN-SIG", "desc": "d" * 90}]}
    txt = fmt_alert(rec2)
    assert "0xabc" in txt and "HIGH" in txt and "BYTECODE-FH-TOKEN-SIG" in txt \
        and "#123" in txt and "字节码指纹" in txt and "PoC报告" in txt
    ok.append("告警格式(含指纹/报告)")

    # 10) 落盘往返 + 500 条截断
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "h.json")
        for i in range(510):
            append_hit({"i": i}, hits_path=p)
        data = load_json(p, [])
        assert len(data) == 500 and data[-1]["i"] == 509, f"截断异常: {len(data)}"
    ok.append("落盘往返+截断")

    # 11) CHAINS 配置完整性（含 BSC 事件模式必需字段）
    for ck, cc in CHAINS.items():
        assert cc["rpcs"] and cc["explorer_api"].startswith("https") and cc["name"]
        assert cc["mode"] in ("receipts", "events")
        if cc["mode"] == "events":
            assert cc.get("factory") and cc.get("topic0") and cc.get("base_tokens")
    ok.append("链配置")

    print(f"✅ monitor selftest 通过 ({len(ok)}组): {' | '.join(ok)}")
    return True


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if "selftest" in args:
        selftest()
        return
    chains = list(CHAINS)
    if "--chain" in args:
        chains = [c.strip() for c in args[args.index("--chain") + 1].split(",") if c.strip()]
        for c in chains:
            assert c in CHAINS, f"未知链: {c}（可选: {', '.join(CHAINS)}）"
    if "--addr" in args:
        addr = args[args.index("--addr") + 1]
        if not re.match(r"^0x[0-9a-fA-F]{40}$", addr):
            print("❌ 地址格式错误")
            sys.exit(1)
        scan_single_address(chains[0], addr)
        return
    once = "--once" in args
    if len(chains) == 1:
        run_chain(chains[0], once=once)
        return
    threads = [threading.Thread(target=run_chain, args=(c, once), daemon=True,
                                name=f"ws-mon-{c}") for c in chains]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
