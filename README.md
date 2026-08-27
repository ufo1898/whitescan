# WhiteScan 🔍

AI 驱动的 Solidity 智能合约漏洞扫描器。标准库单文件，零依赖，20 条漏洞规则 + 免费大模型语义复核。

## 特性

- **零依赖**：纯 Python 3.9+ 标准库（macOS/Linux 直接跑）
- **GitHub 批量发现**：按关键词批量找借贷协议 fork，自动拉取 .sol 源码
- **20 条规则**：首存攻击 / ERC-4626 通胀 / 签名重放 / 回调仿冒 / 预言机操纵 / 滑点缺失 / 未验证返回值 / delegatecall 注入 / tx.origin / 时间戳依赖等
- **AI 语义复核**：正则初筛命中后调 LLM 判定真伪，能拦误报（如存款型 mint 被误判 UNPROTECTED-MINT）
- **Markdown 报告**：一键生成含 AI 判定理由的审计报告
- **三种用法**：CLI / Web 界面 / HTTP API
- **自更新**：`update` 子命令对比 GitHub 最新版自动升级

## 快速开始

```bash
# 自检（验证规则库完整性）
python3 whitescan.py selftest

# 扫描 GitHub 上的借贷 fork（前5个仓库）
python3 whitescan.py scan --limit 5

# 对命中项做 AI 复核（需要 ai_key.txt）
python3 whitescan.py ai --min-sev HIGH

# 生成 Markdown 报告
python3 whitescan.py report -o report.md

# 环境自检
python3 whitescan.py doctor

# 启动 Web 界面（默认 8710 端口）
python3 whitescan_web.py

# 自更新到 GitHub 最新版
python3 whitescan.py update
```

## 凭证（可选）

- `github_token.txt`：GitHub token，提升搜索配额（无 token 少量可用）
- `ai_key.txt`：OpenAI 兼容 API key，用于 AI 复核

## 定时运行（macOS launchd）

```bash
cp com.whitescan.scan.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.whitescan.scan.plist
```

## 免责声明

仅供安全研究与授权测试使用。
