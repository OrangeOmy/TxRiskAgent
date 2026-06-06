# SignShield: AI Pre-signature Risk Copilot for Web3 Wallets

## 1. 项目名称

**SignShield / TxRiskAgent**

AI Pre-signature Risk Copilot for Web3 Wallets

## 2. 一句话介绍

SignShield 是一个面向 Web3 钱包的 AI 签名前风险解释层：在用户点击 Confirm / Sign 之前，解析交易 calldata、识别资产与权限影响、聚合模拟与链上风险证据，并用普通用户能理解的语言给出风险等级和操作建议。

## 3. 背景与痛点

Web3 用户在使用陌生 dApp、领取空投、mint NFT、授权交易、swap 或调用复杂合约时，钱包弹窗通常只展示低层字段：`to`、`value`、`data`、gas fee、签名 payload。普通用户很难判断这笔交易到底会不会转走资产、授权第三方、暴露 NFT collection 权限，或与未验证合约交互。

典型风险包括：

- **ERC20 无限授权**：用户以为只是 claim、swap 或验证钱包，实际调用 `approve(spender, uint256.max)`。
- **Permit / Permit2 签名授权**：用户以为 gasless 签名无害，实际授予 spender 后续转走 token 的权限。
- **NFT 全集授权**：`setApprovalForAll(operator, true)` 允许 operator 转走某 collection 下全部 NFT。
- **隐藏在 multicall / router 里的操作**：前端展示一个动作，但 calldata 中包含多个内部调用。
- **未知或未开源合约**：selector 无法识别、源码未验证、proxy implementation 不透明。
- **高风险 token 交互**：token 可能存在 owner 权限、可增发、高税、honeypot、无法卖出、LP 未锁定等风险。
- **钓鱼来源与恶意地址**：origin domain、spender、operator、contract 可能命中第三方风险情报。

核心痛点不是用户完全没有风险提示，而是现有提示往往缺少三个东西：

- **可解释性**：为什么危险，影响哪个资产，攻击者能做什么。
- **事实基础**：风险结论是否来自 calldata、模拟、合约透明度、情报源，还是模型猜测。
- **签名前时机**：风险提示必须发生在用户点击 Confirm / Sign 之前。

## 4. 解决方案

SignShield 将钱包交易请求转化为结构化风险报告。系统接收 EVM 交易 JSON，完成输入标准化、calldata 解码、风险分支分类、可选 live evidence 聚合、规则评分、用户解释生成，并输出 `riskLevel`、`recommendedAction`、`intent`、`assetImpact`、`riskFactors`、`evidence`、`summary` 和 `recommendation`。

设计原则：

- **Simulation first, AI second**：先用链上事实、解码结果、模拟结果和风险情报建立证据，再让 AI 解释。
- **Explainable risk**：不仅给红灯，还说明风险来源、资产影响和建议动作。
- **Composable architecture**：核心能力以 Skill / API / MCP-ready tool boundary 的方式组织，可被钱包、dApp、agent、浏览器插件或 Snap 调用。
- **Deterministic fallback**：在黑客松现场 API 不稳定时，也可以用 offline fixtures 演示完整流程。

## 5. 核心功能

### 5.1 交易输入标准化

- 支持 `chainId`、`transactionOrigin`、`transaction` 格式。
- 支持 CAIP-2 链 ID，例如 `eip155:1`。
- 支持钱包交易对象中的 `from`、`to`、`data`、`value` 等字段。
- 支持 HTTP API 和 CLI 两种调用方式。

### 5.2 Calldata 解码与意图分类

当前风险分支包括：

| 分类 | 说明 |
| --- | --- |
| `NATIVE_TRANSFER` | 原生资产转账，例如 ETH / BNB / MATIC 流出。 |
| `ERC20_APPROVAL` | `approve`、Permit / Permit2 风险授权。 |
| `NFT_APPROVAL` | `setApprovalForAll` 等 NFT collection 级权限。 |
| `TOKEN_TRANSFER` | ERC20 `transfer` / `transferFrom`。 |
| `MULTICALL` | `multicall`、router `execute`、打包调用。 |
| `UNKNOWN_CONTRACT` | 未知 selector、未开源合约、证据不足的合约调用。 |
| `UNSUPPORTED_CHAIN` | 非 EVM 链或当前不支持链。 |

### 5.3 ERC20 Token Risk Profile

对于 ERC20 交互，系统会构建 token risk profile，覆盖：

- owner 权限与 ownership 状态。
- hidden owner / regain ownership。
- mintable / 可增发。
- high tax / tax mutable。
- cannot sell / honeypot 类风险。
- proxy/source transparency。
- bytecode risk signals。
- holder concentration。
- LP lock facts。

### 5.4 Live Evidence Adapters

项目支持可选 live enrichment：

- Tenderly transaction simulation。
- Etherscan V2 / Blockscout contract reputation。
- GoPlus token threat intelligence。
- MetaMask eth-phishing-detect domain checks。
- Sourcify / OpenChain / 4byte selector resolution。
- Public EVM RPC fallback for token metadata。

缺失的 API key 或 provider failure 会进入 `evidence.limitations` 和 `providerHealth`，不会直接中断分析。

### 5.5 用户可读解释

系统输出中文普通语言总结，例如：

> 这不是普通空投领取，而是在授权陌生 spender 无限花费你的 LAB-USDC。建议拒绝该交易。

## 6. 技术架构

```text
Wallet / dApp / Snap / Demo UI
        |
        v
HTTP API / CLI / Skill Entry
        |
        v
DefenseRuntime
        |
        v
Input Normalizer
        |
        v
Evidence Orchestrator
        |
        +--> Calldata Resolver
        +--> Tenderly Simulation
        +--> Etherscan / Blockscout Contract Reputation
        +--> GoPlus / MetaMask Threat Intel
        +--> RPC Token Metadata
        +--> Offline Fixture Provider
        |
        v
Rule Engine + Decision Engine
        |
        v
Structured Risk Report
        |
        v
AI / User-facing Explanation
```

核心代码位置：

| 模块 | 路径 |
| --- | --- |
| Skill 定义 | `skills/signshield-risk/SKILL.md` |
| CLI 入口 | `skills/signshield-risk/scripts/analyze_evm_tx.py` |
| HTTP 服务 | `skills/signshield-risk/scripts/signshield/http_service.py` |
| Runtime | `skills/signshield-risk/scripts/signshield/runtime.py` |
| Analyzer | `skills/signshield-risk/scripts/signshield/analyzer.py` |
| Evidence Orchestrator | `skills/signshield-risk/scripts/signshield/evidence.py` |
| Rules / Decision | `skills/signshield-risk/scripts/signshield/rules.py`, `decision.py` |
| Fixtures | `dump-tx/` |
| Snap Demo | `apps/snap/` |

## 7. Agent / MCP / Skills 设计

### 7.1 Skill 设计

当前核心 Skill 是 `signshield-risk`。它定义了一套 EVM 签名前风险分析流程：

1. Normalize input。
2. Build fact layer。
3. Classify intent。
4. Apply airdrop / claim overlay when needed。
5. Score risk domains。
6. Explain only structured facts。

Skill 的关键原则是：**模型不直接判断交易安全，而是调用确定性分析流程，基于结构化事实生成解释。**

### 7.2 MCP-ready Tool Boundary

当前仓库已经具备 MCP tool 化所需的边界，但完整 MCP server 仍属于下一步规划。建议拆成以下 tools：

| Tool | 输入 | 输出 |
| --- | --- | --- |
| `decode_calldata` | `chainId`, `to`, `data` | function selector、函数名、参数、标准接口识别。 |
| `simulate_transaction` | transaction request | balance diff、allowance diff、internal calls、logs、revert reason。 |
| `scan_approval_risk` | decoded call, token metadata | spender/operator、授权额度、是否无限授权。 |
| `check_contract_reputation` | `chainId`, contract address | source verification、proxy、deployment、labels、history。 |
| `check_domain_reputation` | origin URL | phishing list hit、domain risk、source confidence。 |
| `build_token_risk_profile` | token address | owner、mint、tax、honeypot、LP、holder facts。 |
| `risk_score` | normalized evidence | risk level、score、confidence、recommended action。 |
| `generate_user_warning` | structured risk report | 普通语言解释和用户建议。 |

### 7.3 Agent Goal / Context

在 Agent 语义中：

- **Goal**：本次任务目标，例如“判断用户是否应该签这笔交易”。
- **Context**：Agent 判断所需背景，例如交易 JSON、origin、合约信息、模拟结果、token profile、phishing 情报、provider health。

示例：

```text
Goal:
Decide whether the user should sign this wallet transaction.

Context:
- chainId: eip155:1
- origin: http://127.0.0.1:5173/claim-lab-usdc
- decoded function: approve(address,uint256)
- spender: 0x3000...0001
- amount: uint256.max
- token profile: LAB-USDC fixture, owner/mint/tax risk present
```

## 8. 使用流程

### 8.1 用户视角

1. 用户访问 dApp。
2. dApp 发起交易或签名请求。
3. 钱包 / Snap / Demo UI 将交易 JSON 发送给 SignShield。
4. SignShield 返回结构化风险报告。
5. 用户看到风险等级、资产影响、证据链和建议。
6. 用户选择拒绝、继续、降低授权额度或使用隔离钱包。

### 8.2 开发者视角

1. 将钱包交易对象传给 `/tx-scan`。
2. 读取 `verdict.recommendedAction` 和 `riskFactors`。
3. 在钱包确认页、dApp 前端或 agent workflow 中展示解释。
4. 对 `CRITICAL` / `HIGH` 交易进行强提示或阻断。

## 9. Demo 示例

### Demo 1: Fake Airdrop Claim -> ERC20 Unlimited Approval

用户点击 `Claim LAB-USDC airdrop`，以为是在领取空投。实际交易为：

```text
approve(0x3000000000000000000000000000000000000001, uint256.max)
```

预期输出：

```json
{
  "verdict": {
    "riskLevel": "CRITICAL",
    "recommendedAction": "REJECT"
  },
  "intent": {
    "category": "ERC20_APPROVAL",
    "decodedFunction": "approve(address,uint256)"
  },
  "summary": "这不是普通页面确认，而是在授权 0x3000...0001 花费你的 LAB-USDC，额度接近无限。"
}
```

### Demo 2: NFT Verify -> setApprovalForAll

用户以为是在验证 NFT 持有资格，实际调用：

```text
setApprovalForAll(operator, true)
```

风险解释：

- 该操作允许 operator 转移这个 NFT collection 下的全部 NFT。
- 如果 operator 是陌生或高风险地址，建议拒绝。

### Demo 3: Multicall Hidden Approval / Transfer

用户看到单个 claim 操作，但交易包里隐藏多个调用。系统将其分类为 `MULTICALL`，并在证据不足或发现内嵌授权时提高风险等级。

### Demo 4: ERC20 Token Risk Profile

系统对 ERC20 token 生成风险画像，识别 owner 权限、可增发、高税、honeypot、LP 未锁定、holder concentration 等风险，并把 token 风险纳入最终评分。

## 10. 安装与运行方式

### 10.1 环境要求

- Python `>=3.11`
- `uv` 推荐，但不是必须
- Node.js / npm 用于 Snap demo
- 可选 API key：Tenderly、Etherscan、GoPlus、OpenAI-compatible LLM

### 10.2 Python 分析器

使用 `uv`：

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

单文件分析：

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py \
  dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json \
  --summary-llm off
```

没有 `uv` 时：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi openai pyyaml requests uvicorn pytest httpx
python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

### 10.3 HTTP API

本地 demo 模式：

```bash
export TX_RISK_API_KEY=
export SIGNSSHIELD_HTTP_MODE=offline
export SIGNSSHIELD_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173

uv run uvicorn signshield.http_service:app \
  --app-dir skills/signshield-risk/scripts \
  --host 127.0.0.1 \
  --port 8000
```

生产风格模式：

```bash
export TX_RISK_API_KEY=your-local-api-key
export SIGNSSHIELD_HTTP_MODE=production

uv run uvicorn signshield.http_service:app \
  --app-dir skills/signshield-risk/scripts \
  --host 127.0.0.1 \
  --port 8000
```

调用接口：

```bash
curl -X POST http://127.0.0.1:8000/tx-scan \
  -H "X-API-Key: $TX_RISK_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json
```

### 10.4 Snap Demo

```bash
cd apps/snap
npm ci
npm start
```

默认服务：

- Demo UI: `http://127.0.0.1:5173`
- Local Snap: `http://localhost:8081`

注意：本地 Snap 安装通常需要 MetaMask Flask。若普通 MetaMask 不支持 `wallet_requestSnaps`，Demo 会降级为 API-only 模式，仍可测试 TxRiskAgent 风险扫描。

### 10.5 测试

```bash
uv run pytest -q
```

当前本地验证结果：

```text
71 passed
```

## 11. 项目亮点

- **签名前防护**：在用户点击 Confirm / Sign 前输出风险解释。
- **事实优先**：calldata、simulation、contract reputation、token profile、threat intel 先于 AI 解释。
- **结构化输出**：可被钱包、dApp、Agent、后端风控系统直接消费。
- **空投安全 hero demo**：用假 claim -> unlimited approval 展示真实高频攻击路径。
- **ERC20 token risk profile**：不仅看交易行为，也分析 token 自身风险。
- **离线 fixture 可复现**：黑客松现场无需依赖外部 API 也能稳定演示。
- **Live adapter 可扩展**：Tenderly、Etherscan、Blockscout、GoPlus、MetaMask phishing list、public RPC。
- **MCP / Skills 化方向清晰**：当前已沉淀 Skill，可进一步拆成 MCP tools。

## 12. 当前限制

- 当前主要支持 EVM 链，不覆盖 Solana、Sui、Aptos 等非 EVM 生态。
- Tenderly live simulation 需要正确配置 account slug、project slug 和 access key。
- 部分 provider 受 API key、网络、rate limit 影响，因此需要 offline fixture fallback。
- 当前 MCP server 尚未完整封装，项目处于 Skill + HTTP API + CLI 原型阶段。
- Permit2、router multicall 的深度递归解析仍可继续增强。
- Snap 本地安装依赖 MetaMask Flask，普通钱包环境可能只支持 API-only demo。
- LLM summary 依赖 OpenAI-compatible endpoint；网络不可用时应关闭或降级。

## 13. 未来规划

近期计划：

- 完成 MCP server 封装，把核心能力暴露为标准 MCP tools。
- 增强 Permit / Permit2 / EIP-712 typed data 解码。
- 增强 multicall / router / universal router 递归解析。
- 接入更完整的 Tenderly simulation facts，包括 allowance diff 和 balance diff。
- 增加空投合约安全检查：Merkle proof、claim deadline、root update 权限、replay protection。
- 增加用户地址维度的授权扫描和 revoke 建议。
- 完善前端 wallet confirmation mock UI，减少对 MetaMask Flask 的依赖。

中长期计划：

- 支持更多 EVM 网络和主流 L2。
- 构建 phishing domain + malicious spender 的多源聚合评分。
- 支持组织/钱包厂商集成的 policy 配置。
- 支持多语言用户解释。
- 扩展到签名消息、订单签名、授权管理、领取后安全建议。

## 14. 团队分工

> 以下为可替换模板，提交前可填入真实姓名或 GitHub handle。

| 角色 | 负责内容 | 成员 |
| --- | --- | --- |
| Product / Pitch | 项目定位、用户故事、演示脚本、提交文档 | TODO |
| Risk Engine | calldata 解码、规则评分、risk report schema | TODO |
| Live Integrations | Tenderly、Etherscan、Blockscout、GoPlus、RPC | TODO |
| Agent / Skills | Skill 流程、MCP tool boundary、subagent context | TODO |
| Frontend / Demo | Snap demo、wallet confirmation UI、交互演示 | TODO |
| Research / Fixtures | 空投安全案例、dump-tx fixtures、测试语料 | TODO |
| Testing / DevOps | pytest、CI、本地启动脚本、现场 fallback | TODO |

## 15. License / Contact

### License

This project is licensed under the Apache License 2.0. See `LICENSE` for details.

### Repository

- Fork: <https://github.com/hkun0120/TxRiskAgent.git>
- Upstream: <https://github.com/OrangeOmy/TxRiskAgent.git>

### Contact

- Team name: TODO
- Primary contact: TODO
- Email / Telegram / Discord: TODO
- Demo URL / Video: TODO
