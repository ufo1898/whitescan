## [1.4.0] - 2026-08-28

### 新增: 链上新合约实时监控器 (whitescan_monitor.py)
- 轮询公共 RPC (publicnode/1rpc/drpc 故障转移) 抓新部署合约(eth_getBlockReceipts, 覆盖 CREATE2 工厂)
- Blockscout 免费拉已验证源码 -> 复用 24 条规则引擎 -> HIGH/MED 实时告警
- 多链支持(主网/Sepolia), state/hits 按链分文件防块高互串
- --once 单轮 / --addr 手动深扫 / selftest 离线自检 / WHITESCAN_ALERT_WEBHOOK 告警推送
- Web 看板新增「链上实时监控」板块 + /api/monitor 端点(30s 自动刷新)
- systemd 服务 whitescan-monitor 常驻(Restart=always, MemoryMax=150M)
- 首战验证: 主网新部署 FashUSDTLiquidityBot 等蜜罐特征合约 1 块内捕获(重入/tx.origin/弱随机)

## [1.3.2] - 2026-08-28

### Fixed
- `UNCHECKED-TRANSFER` 精度修复：不再误报原生币 `payable(x).transfer()`（失败自动 revert，无需检查返回值），只检测 ERC20 转账返回值丢弃；样例同步更新为真 ERC20 形态
- `REENTRANCY` 精度修复（CEI 语义）：只报「外部调用之后仍有状态写入」的经典重入模式；纯提款与 call 前完成状态写（CEI 安全模式）不再误报

### Changed
- 搜索 query 12 → 16：新增 price oracle / governance timelock / token vesting / multisig wallet 赛道（依据 2026 年 6-8 月盗币事件复盘攻击面扩展）

# Changelog

本文件记录 WhiteScan 的版本变更。格式参考 Keep a Changelog。

## [1.3.0] - 2026-08-28

### Added
- 基于近期实战盗币事件复盘新增 4 条规则（20 → 24）：
  - `TIMELOCK-ZERO`（HIGH）：治理 timelock delay 可经 setter 清零 —— 复盘 Term Finance 2026-08-24 $8.5M 治理攻击
  - `CROSSCHAIN-SIG-REPLAY`（HIGH）：跨链消息验签缺 chainId/nonce —— 复盘 2026-06-14 三协议桥 $127M 签名重放
  - `HARDCODED-AUTH-SECRET`（MED）：硬编码字符串鉴权 —— 复盘 SquidRouterModule 2026-05 $3.2M
  - `LEGACY-LIVE-CONTRACT`（LOW）：弃用合约入口仍可调用 —— 复盘 Transit Finance 2026-05 $1.88M
- selftest 矩阵同步扩至 24/24（漏洞必中 + 安全零误报）

### 事件背景（2026 H1 数据）
- H1 2026 共 212 起安全事件，损失 $1.1B（Blockaid），为史上最惨半年
- 凭据/私钥类攻击占事件数 15% 却占损失金额 76%；合约代码漏洞仍是事件数主力（125/207）
- 2026-08 单月 17 起，Term Finance $8.5M 治理攻击为本月代表

## [1.2.0] - 2026-08-28

### Added
- 全规则测试矩阵：selftest 覆盖 20/20 条规则（漏洞样例必中 + 安全样例零误报 + 覆盖率断言），规则数与矩阵数不符直接失败
- 边界测试：空输入 / 非 Solidity 文本 / 600KB 超长输入不崩溃
- AI 调用重试：网络错误 / 5xx / 429 指数退避重试 3 次，4xx 立即失败（`_http_json`）
- `scan --ai`：扫描完成直连 AI 复核命中项，一条命令出最终结论
- `scan/ai --min-sev HIGH|MED|ALL`：按严重级过滤 AI 复核对象，省 token
- `scan --source dir` 递归子目录扫描（此前只扫顶层）
- Web 版 token 鉴权（`WHITESCAN_WEB_TOKEN`，query 参数或 X-Token 头）
- Web 版请求体 500KB 硬限 + Content-Length 强制校验（超限 413）
- GitHub Actions CI：push/PR 自动跑 selftest（3.8/3.11/3.12 三版本矩阵）
- README 规则表 + 完整用法文档

### Changed
- Web 服务改 `ThreadingHTTPServer`（此前单线程，一个慢请求卡死全部）
- Web 并发保护：GitHub 抓取串行锁（配额保护）、AI 复核并发上限 2、总并发 16
- `UNCHECKED-CALL` / `UNCHECKED-TRANSFER` 守卫正则改按语句分界（`;`）匹配，`require(x.call(...))` 内联写法不再漏报

### Fixed
- **Web 自死锁**：`threading.Lock` 不可重入，do_POST 与 fetch_code_from_input 同线程二次加锁导致永久挂起 —— 锁职责统一收归 HTTP 层
- **AI 复核 --min-sev 失效**：targets 过滤后循环仍遍历全量 records，过滤形同虚设
- Web URL 抓取绕过代理：改走 `ws._opener()`（修复 008 等代理环境）
- 401 等客户端错误不再无意义重试

## [1.1.1] - 2026-08-27

### Added
- `VERSION` 文件 + `update` 自更新子命令（拉 GitHub raw 比对版本）
- `WHITESCAN_PROXY` 代理支持：8 处 urlopen 全走 `_opener()`（ProxyHandler）
- Web 版（whitescan_web.py）：贴码 / repo / URL 三种输入 + AI 复核

### Changed
- 版本号统一 v1.1.1

## [1.1.0] - 2026-08-27

### Added
- GitHub 首次发布：whitescan.py + whitescan_web.py + launchd plist
- 14 → 20 条漏洞规则（ERC-4626 通胀 / 签名重放 / 回调未验证 / 弱随机 / 循环 DoS / swap deadline）
- AI 语义复核层（b.ai glm-5.3-flash）
- 本地目录扫描 / Markdown 报告 / selftest
