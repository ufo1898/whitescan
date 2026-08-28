# WhiteScan 🛡️

零依赖智能合约漏洞扫描器 — 单文件 Python 标准库，macOS/Linux 直接跑（无需 pip）。

**静态规则扫描 + AI 语义复核** 双引擎：20 条规则初筛，大模型复核降误报，专为批量筛 Compound fork / 借贷协议设计的白帽狩猎工具。

## 特性

- **零依赖**：Python 3.8+ 标准库，单文件部署， Mac mini / VPS 通吃
- **20 条漏洞规则**：首存攻击、预言机操纵、任意 delegatecall、ERC-4626 通胀、签名重放……
- **AI 语义复核**：静态命中 → 大模型逐条判定真漏洞/误报（OpenAI 兼容接口，默认 glm-5.3-flash）
- **增量落盘**：扫描中断结果不丢，实时写 scan_results.json
- **网络韧性**：AI 调用 3 次指数退避重试；代理支持（`WHITESCAN_PROXY`）
- **Web 界面**：内置网页版（多线程、body 硬限、SSRF 白名单、可选 token 鉴权）
- **自更新**：`update` 子命令拉 GitHub VERSION 自动升级

## 快速开始

```bash
# 批量扫 GitHub（Compound fork 搜索）
python3 whitescan.py scan --limit 10

# 扫本地目录（递归 .sol）
python3 whitescan.py scan --source dir --target /path/to/contracts

# 扫完直连 AI 复核（只审 HIGH，最多10项）
python3 whitescan.py scan --source dir --target ./contracts --ai

# AI 复核已有结果（按严重级过滤）
python3 whitescan.py ai scan_results.json --min-sev HIGH   # 只审含 HIGH 的
python3 whitescan.py ai scan_results.json --min-sev MED    # 审 HIGH+MED
python3 whitescan.py ai scan_results.json --min-sev ALL    # 全审

# 自检（20/20 规则矩阵 + 边界输入）
python3 whitescan.py selftest

# 网页版（默认 127.0.0.1:8710）
python3 whitescan_web.py

# 自更新
python3 whitescan.py update
```

## 规则表

| 规则 ID | 级别 | 说明 |
|---|---|---|
| `COMPOUND-V2-FIRST-DEPOSITOR` | HIGH | 第一笔存款攻击(抽干后入者) |
| `ORACLE-SPOT-PRICE` | HIGH | 预言机spot价格操纵 |
| `UNPROTECTED-INITIALIZER` | HIGH | 未保护initialize |
| `ARBITRARY-DELEGATECALL` | HIGH | 任意delegatecall |
| `UNPROTECTED-MINT` | HIGH | 未保护mint(无限增发) |
| `REENTRANCY` | MED | 重入攻击 |
| `SELFDESTRUCT` | MED | 未保护selfdestruct |
| `UNCHECKED-CALL` | MED | 未检查call返回值 |
| `INTEGER-OVERFLOW` | MED | 整数溢出(<0.8无SafeMath) |
| `PROXY-STORAGE-COLLISION` | MED | 代理存储冲突 |
| `TX-ORIGIN` | LOW | tx.origin鉴权 |
| `MISSING-ZERO-CHECK` | LOW | 缺零地址检查 |
| `BLOCK-TIMESTAMP` | LOW | 时间戳依赖 |
| `UNCHECKED-TRANSFER` | LOW | 未检查transfer返回值 |
| `ERC4626-INFLATION` | HIGH | ERC-4626通胀攻击 |
| `SIGNATURE-REPLAY` | HIGH | 签名重放(缺nonce/deadline/chainId) |
| `UNPROTECTED-CALLBACK` | HIGH | 回调未验证调用方 |
| `WEAK-RANDOMNESS` | MED | 弱随机数 |
| `UNBOUNDED-LOOP-DOS` | MED | 无上限循环DoS |
| `MISSING-SWAP-DEADLINE` | LOW | swap无deadline |
| `TIMELOCK-ZERO` | HIGH | 治理timelock可清零 |
| `CROSSCHAIN-SIG-REPLAY` | HIGH | 跨链消息签名重放 |
| `HARDCODED-AUTH-SECRET` | MED | 硬编码鉴权串 |
| `LEGACY-LIVE-CONTRACT` | LOW | 弃用合约仍可调用 | | | `TAX-BURN-FROM-POOL` | HIGH | 通缩税烧池子+主动sync（FH Token 2026-08-26 $20K 实战提炼） |

## 配置（环境变量 / 凭证文件）

| 配置 | 说明 |
|---|---|
| `WHITESCAN_PROXY` | HTTP 代理（如 `http://127.0.0.1:10900`），GitHub/AI 请求全走此代理 |
| `WHITESCAN_AI_KEY` | AI key（优先）；否则读同目录 `ai_key.txt` |
| `WHITESCAN_AI_BASE` | OpenAI 兼容 base URL（默认 `https://api.b.ai/v1`） |
| `WHITESCAN_AI_MODEL` | 模型名（默认 `glm-5.3-flash`） |
| `WHITESCAN_WEB_TOKEN` | 设置后 Web /api/scan 需 token（`?token=` 或 `X-Token` 头） |
| `github_token.txt` | 同目录，GitHub API token（提额） |

## Web 版

```bash
python3 whitescan_web.py   # http://127.0.0.1:8710
```

安全设计：仅监听 127.0.0.1（公网走 nginx 反代 + 随机路径）、GitHub 域名白名单防 SSRF、
body 500KB 硬限、GitHub 抓取串行锁 + AI 并发上限 2、可选 token 鉴权。

## 定时任务（macOS launchd 示例）

`com.whitescan.scan.plist` 已含绝对路径 + 代理环境变量，每日 10:00 自动扫描：

```bash
cp com.whitescan.scan.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.whitescan.scan.plist
```

## 免责声明

仅供授权安全研究 / 白帽漏洞赏金使用。发现漏洞请走负责任披露，勿用于非法用途。

## License

MIT

## 🔴 链上新合约实时监控 (v1.4.0+)

新部署合约 1 个区块内自动扫描 + 告警：

```bash
# 常驻监控主网(推荐 systemd)
python3 whitescan_monitor.py

# 单轮/测试网/手动深扫/自检
python3 whitescan_monitor.py --once
python3 whitescan_monitor.py --chain sepolia
python3 whitescan_monitor.py --addr 0x...
python3 whitescan_monitor.py selftest
```

- 数据源: publicnode/1rpc/drpc RPC 故障转移 + Blockscout 已验证源码(均免费无 key)
- 覆盖普通创建 + CREATE2 工厂部署(eth_getBlockReceipts)
- 告警: HIGH/MED 命中写 monitor_hits_*.json + 可选 WHITESCAN_ALERT_WEBHOOK webhook
- 每块上限 30 合约、源码 200KB 上限、轮询异常自动重试，永不因单合约故障中断
