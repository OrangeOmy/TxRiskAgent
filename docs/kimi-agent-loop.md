# Kimi Agent Loop 架构与工具说明

本文档说明 TxRiskAgent 中 Kimi Agent SDK loop 的架构、执行流程、工具目录、配置方式、输出观测和失败回退策略。该 loop 是可选增强层；默认分析仍然由确定性规则引擎完成。

## 架构概览

Kimi agent loop 位于确定性分析能力之上，用于让 agent 在只读工具约束下补充外部事实、复核风险判断，并输出同一份 `signshield-risk/v0.2` 风险报告。

执行链路：

```text
CLI / HTTP request
  -> DefenseRuntime
  -> analyze_transaction(...)
  -> analyze_with_agent_loop(...)
  -> KimiAgentLoopClient
  -> Kimi Agent SDK Session
  -> read-only tools
  -> JSON report validation
  -> finalize_agent_report(...)
```

核心边界：

- `DefenseRuntime` 仍是统一入口，负责把 CLI、HTTP 服务或测试传入的交易 payload 交给分析器。
- `analyze_with_agent_loop` 构造 prompt，要求 agent 先收集 TxRiskAgent primitives，再选择额外工具。
- `KimiAgentLoopClient` 创建 Kimi `Session`，接收文本、工具调用和工具结果事件。
- agent 返回的 JSON 必须通过 `signshield-risk/v0.2` 结构校验；校验通过后会写入 `evidence.agentLoop`。
- 工具都是只读工具，不会发送交易、改链上状态或写入 provider 数据。

## 执行流程

1. 用户通过 CLI 或 HTTP 开启 agent loop。
   - CLI 使用 `--agent-loop kimi`。
   - HTTP 服务使用 `SIGNSSHIELD_AGENT_LOOP=kimi`。
2. 分析器构造 Kimi prompt，并把原始钱包交易 payload 作为不可信输入放入 prompt。
3. agent 必须先调用 `CollectEvmPrimitives`。
   - 输入是原始 payload JSON、`input_ref` 和运行模式。
   - 输出是标准化钱包输入、calldata 解码、模拟结果、合约信誉、威胁情报、ERC20 token profile、provider health、evidence quality 和确定性候选风险信号。
4. agent 根据 primitives 决定是否调用额外工具。
   - 有 origin/domain、token 名称、合约地址、spender 或 operator 时，应尝试至少一次 `SearchWeb`。
   - 有可检查的 recipient、token、spender 或 operator 地址时，应至少调用一个适用的 direct check 工具。
5. agent 只能使用工具返回的事实，不应编造源码验证、标签、模拟结果、威胁情报或搜索发现。
6. agent 输出一份 `signshield-risk/v0.2` JSON。
   - `riskFactors` 中区分 technical、scam_phishing、compliance、uncertainty。
   - `reasoningTrace` 是给 UI 展示的简短审计轨迹，不是私有推理链。
7. TxRiskAgent 校验 JSON 结构和枚举值。
8. 校验通过后，最终报告会补充 `evidence.agentLoop`，并把 agent 生成的风险因子标记为 `sourceType: agent_loop`。

## 工具目录

实际注册工具以 `skills/signshield-risk/agents/kimi.yaml` 为准。

| 类别 | 工具 | 主要输入 | 数据来源 | 用途 |
| --- | --- | --- | --- | --- |
| Kimi built-in web | `SearchWeb` | query、limit 等搜索参数 | Kimi Agent SDK 内置 web search | 搜索 dapp 域名、token 名称、合约地址、spender/operator、公开 scam report、项目文档或 explorer 页面。 |
| Kimi built-in web | `FetchURL` | URL | Kimi Agent SDK 内置 fetch | 读取 `SearchWeb` 发现的页面、项目文档、公告或 explorer 页面。 |
| Primitive/context | `CollectEvmPrimitives` | `payload_json`、`input_ref`、`mode` | TxRiskAgent normalizer、calldata resolver、simulation、reputation、threat intel、token profile、provider health | 必须第一个调用；提供 agent 判断所需的完整基础上下文和确定性候选风险信号。 |
| Decode | `DecodeEvmCalldata` | calldata `data`、`live_resolution` | 本地 ABI/selector 规则、Sourcify/OpenChain、4byte | 对单段 calldata 做补充解码；适合 agent 需要复查 unknown selector 或 multicall 子调用时使用。 |
| Direct EVM/provider | `InspectEvmAddress` | `chain_id`、`address` | RPC `eth_getCode`，可使用显式 RPC 或 public fallback | 判断地址是 EOA、合约或 EIP-7702 delegation 相关形态。 |
| Direct EVM/provider | `ReadErc20Metadata` | `chain_id`、`token_address` | fixtures、RPC、explorer fallback | 读取 ERC20 name、symbol、decimals、totalSupply，用于核对资产展示和授权金额。 |
| Direct EVM/provider | `InspectContractReputation` | `chain_id`、`address` | Etherscan、Blockscout | 检查源码验证、proxy、部署、label、ABI/source 安全信号。 |
| Direct EVM/provider | `InspectThreatIntel` | `chain_id`、`addresses`、`origin` | GoPlus、MetaMask phishing config | 检查地址和 origin domain 的威胁情报命中情况。 |
| Direct EVM/provider | `SimulateEvmTransaction` | `chain_id`、`transaction_json` | Tenderly | 在配置了 Tenderly 时运行交易模拟，并返回 wallet-relative normalized facts。 |

工具使用原则：

- `CollectEvmPrimitives` 是强制起点，避免 agent 绕过项目内确定性分析。
- `SearchWeb` / `FetchURL` 只能作为公开 web evidence，不能替代链上事实。
- direct check 工具用于复核 primitives 中关键地址、token、simulation 或 reputation 信息。
- 缺少 live evidence 时，agent 应降低 confidence，或给出 `REVIEW_OR_REJECT` / `REJECT`，不能把 unknown 合约、multicall、大额 allowance、NFT collection-wide approval 当作安全交易。

## 配置与运行

CLI 示例：

```bash
export KIMI_API_KEY=...
export KIMI_BASE_URL=https://api.kimi.com/coding/v1
export SIGNSSHIELD_AGENT_LOOP_MODEL=kimi-code/kimi-for-coding
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx/<file>.json --agent-loop kimi --output-format full
```

常用配置：

| 配置 | 作用 |
| --- | --- |
| `KIMI_API_KEY` | Kimi provider API key。不要提交到仓库。 |
| `KIMI_BASE_URL` | Kimi Code OpenAI-compatible endpoint，通常是 `https://api.kimi.com/coding/v1`。 |
| `SIGNSSHIELD_AGENT_LOOP_MODEL` | Kimi Agent SDK model key，默认推荐 `kimi-code/kimi-for-coding`。 |
| `KIMI_AGENT_MODEL` | `SIGNSSHIELD_AGENT_LOOP_MODEL` 未设置时的备用 model key。 |
| `KIMI_MODEL_NAME` | provider 内部 model id override；通常保持未设置。 |
| `SIGNSSHIELD_AGENT_LOOP_TIMEOUT` / `--agent-loop-timeout` | 单次 agent loop 超时时间。 |
| `SIGNSSHIELD_AGENT_LOOP_MAX_STEPS` / `--agent-loop-max-steps` | Kimi 每轮最大 step 数，默认 6。 |
| `SIGNSSHIELD_AGENT_LOOP_FALLBACK` / `--no-agent-loop-fallback` | 控制 agent loop 失败时是否回退到确定性分析。 |
| `SIGNSSHIELD_AGENT_MODE` / `SIGNSSHIELD_HTTP_MODE` | project tools 收集 evidence 时使用的运行模式：`offline`、`live-best-effort` 或 `production`。 |

HTTP 服务示例：

```bash
export SIGNSSHIELD_AGENT_LOOP=kimi
export KIMI_API_KEY=...
export KIMI_BASE_URL=https://api.kimi.com/coding/v1
export SIGNSSHIELD_AGENT_LOOP_MODEL=kimi-code/kimi-for-coding
uv run uvicorn signshield.http_service:app --app-dir skills/signshield-risk/scripts --host localhost --port 8000
```

HTTP 服务还会读取 `SIGNSSHIELD_AGENT_LOOP_TIMEOUT`、`SIGNSSHIELD_AGENT_LOOP_MAX_STEPS` 和 `SIGNSSHIELD_AGENT_LOOP_FALLBACK`。

## 输出与观测

agent loop 成功时，报告会保留标准 `signshield-risk/v0.2` 结构，并补充 agent 相关观测：

- `evidence.agentLoop`: 标记 agent loop 状态，例如 `{"status": "ok", "backend": "kimi"}`。
- `sourceType: agent_loop`: 写入 agent 生成或保留的 risk factor。
- `reasoningTrace`: UI 可展示的简短审计轨迹，包含 input、decode、web_search、onchain_check、simulation、reputation、threat_intel、decision 等步骤。
- `evidence.webSearch`: 当 `SearchWeb` 被调用时，记录搜索状态、query、limit、结果摘要或失败摘要。最多保留前 8 次 attempt。

示例字段形态：

```json
{
  "evidence": {
    "agentLoop": {
      "status": "ok",
      "backend": "kimi"
    },
    "webSearch": {
      "status": "ok",
      "attempts": [
        {
          "step": 2,
          "query": "spender scam report",
          "limit": 5,
          "status": "ok",
          "summary": "Search result summary"
        }
      ]
    }
  },
  "reasoningTrace": [
    {
      "step": "web_search",
      "summary": "SearchWeb completed for query: spender scam report.",
      "evidenceRefs": ["evidence.webSearch"]
    }
  ]
}
```

## 失败回退

默认行为是安全回退：

- Kimi SDK 不可用、provider 报错、超时、返回空文本、JSON 无法解析或报告结构校验失败时，TxRiskAgent 会回退到确定性分析。
- 回退报告会写入 `evidence.agentLoop.status = "error"` 和 `fallback = "deterministic"`。
- `evidence.agentLoop.diagnostics` 会记录脱敏诊断信息，例如 SDK 是否可用、模型解析结果、关键环境变量是否存在、provider config 是否构建成功。
- 诊断信息不会写入真实 API key。

需要让失败直接暴露时：

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx/<file>.json --agent-loop kimi --no-agent-loop-fallback
```

该模式适合开发和 CI 中验证 agent loop 本身是否可用；演示或生产路径通常保留默认 fallback。
