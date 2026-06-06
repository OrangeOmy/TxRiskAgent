# External Adapters

## CLI Mode

Default mode is offline and deterministic:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

Live mode enables all configured adapters:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --live --output output/risk-reports-live
```

ERC20 subagent modes:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --subagent dry-run --output output/risk-reports-subagent-context
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --subagent live --subagent-command ./agent-command --output output/risk-reports-subagent-live
```

## 1. OpenChain / 4byte Calldata Resolver

Implementation:

- `signshield.adapters.calldata_resolver.SourcifyOpenChainResolver`
- `signshield.adapters.calldata_resolver.FourByteDirectoryResolver`
- `signshield.adapters.calldata_resolver.CombinedCalldataResolver`

Provider behavior:

- Try Sourcify's OpenChain-compatible `https://api.4byte.sourcify.dev/signature-database/v1/lookup`.
- Fall back to 4byte.directory `https://www.4byte.directory/api/v1/signatures/`.
- Store provider details under `evidence.calldata.resolver`.

No API key is required.

## 2. Tenderly Simulation Adapter

Implementation:

- `signshield.adapters.simulation.TenderlySimulationAdapter`

Environment variables:

- `TENDERLY_ACCOUNT_SLUG`
- `TENDERLY_PROJECT_SLUG`
- `TENDERLY_ACCESS_KEY`

Provider behavior:

- Calls Tenderly Simulation API only when all three settings are present.
- Missing settings produce `{"status": "config_missing"}`.
- Sends `network_id`, `from`, `to`, `input`, decimal `value`, numeric gas, and pre-sign state overrides used by full simulation.
- Parses `transaction.transaction_info.asset_changes`, `balance_changes`, logs, revert/error fields, gas used, and call-trace presence.
- Normalized facts are stored under `evidence.simulation.facts` as `asset_change`, `balance_change`, `approval_change`, `revert_or_error`, or `call_trace_present`.
- Rules use wallet-relative facts to flag simulated wallet asset outflows and approval changes.
- Use `source .env && python skills/signshield-risk/scripts/check_integrations.py` for a local Tenderly smoke check.

## 3. Etherscan / Blockscout Contract Adapter

Implementation:

- `signshield.adapters.contract_reputation.CompositeContractReputationAdapter`
- `skills/signshield-risk/scripts/check_etherscan.py`

Environment variables:

- `ETHERSCAN_API_KEY`
- `BLOCKSCOUT_BASE_URL`

Provider behavior:

- Etherscan uses V2 `https://api.etherscan.io/v2/api` with `chainid`.
- `getsourcecode` supplies source verification, ABI summary, compiler/license metadata, proxy and implementation facts, and lightweight source/ABI security signals. Full source code is not stored in output reports.
- `getcontractcreation`, `proxy/eth_getTransactionByHash`, and `proxy/eth_getBlockByNumber` supply deployer, creation tx, deployment timestamp, and age.
- `account/balance`, `account/txlist`, and `account/tokentx` supply account age/activity and recent token-transfer facts.
- Token and nametag endpoints are attempted as best-effort. Pro-only or unavailable endpoints are recorded under `providerLimitations` and must not fail analysis.
- Blockscout uses `/api/v2/smart-contracts/{address}`.
- Missing settings produce provider-specific `config_missing` statuses.
- Parsed facts are stored under `evidence.contractReputation`.

Key check:

```bash
ETHERSCAN_API_KEY=... uv run python skills/signshield-risk/scripts/check_etherscan.py
```

## 4. GoPlus Threat Intel Adapter

Implementation:

- `signshield.adapters.threat_intel.CompositeThreatIntelAdapter`

Environment variables:

- `GOPLUS_BASE_URL`, default `https://api.gopluslabs.io`

Provider behavior:

- Calls `/api/v1/token_security/{chain_id}?contract_addresses=...`.
- Converts high-risk token flags into `goplus_token_security_flags` risk factors.
- Parsed facts are stored under `evidence.threatIntel.providers.goplus`.

## 5. MetaMask Phishing Domain Adapter

Implementation:

- `signshield.adapters.threat_intel.CompositeThreatIntelAdapter`

Environment variables:

- `METAMASK_CONFIG_URL`, default `https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json`

Provider behavior:

- Checks the origin host against MetaMask `blocklist` and `fuzzylist`.
- Respects `allowlist`.
- Adds `phishing_domain_match` risk factor for matches.
- Parsed facts are stored under `evidence.threatIntel.providers.metamask`.

## 6. Public RPC Fallback

Implementation:

- `signshield.rpc.PublicRpcResolver`
- `signshield.rpc.check_public_rpc_endpoints`
- `signshield.token_metadata.TokenMetadataResolver`

Provider behavior:

- Explicit `--rpc-url` or `SIGNSSHIELD_RPC_URL` always takes precedence.
- In `--live` mode, if no explicit RPC is configured, the resolver probes bundled public HTTP RPC endpoints with `eth_chainId` and selects the first endpoint matching the input chain id.
- WebSocket endpoints are registered for visibility but skipped by the current HTTP `eth_call` metadata pipeline.
- Selected endpoint, probe attempts, and metadata call errors are stored under `evidence.erc20TokenRisk.metadata.rpcStatus`.
- Use `--no-public-rpc-fallback` to disable public endpoints in live mode.

Availability check:

```bash
uv run python skills/signshield-risk/scripts/check_public_rpc.py > output/public-rpc-check.json
```

## Testing

Unit tests mock provider responses and do not require live credentials:

```bash
uv run pytest -q
```

Optional smoke checks for no-key providers:

```bash
PYTHONPATH=skills/signshield-risk/scripts uv run python - <<'PY'
from signshield.adapters.calldata_resolver import SourcifyOpenChainResolver
print(SourcifyOpenChainResolver().resolve("0xa9059cbb"))
PY
```

Use live mode for end-to-end enrichment. If credentials are absent, the result remains valid and documents missing providers in `limitations`.

## 7. ERC20 Token Risk Profile

Implementation:

- `signshield.token_metadata.TokenMetadataResolver`
- `signshield.token_security_normalizer.build_erc20_token_risk_profile`
- `signshield.contract_bytecode_scanner.scan_contract_bytecode`
- `signshield.erc20_scoring.apply_erc20_token_profile_rules`

Provider behavior:

- Token metadata uses local fixtures first, optional/selected RPC second, and explorer contract names as fallback.
- GoPlus raw token reports are normalized into the ERC20 token-risk profile fields when available.
- Bytecode scanning is lightweight and only marks selector/opcode presence. It does not prove source-level semantics.
- Missing holder/LP/deployment fields remain `null`.

## 8. Subagent Harness

Implementation:

- `signshield.subagent_context_builder.build_subagent_context`
- `signshield.subagent_harness.run_subagent_harness`

Command protocol:

- The command receives JSON context on stdin.
- The command must print JSON with `status`, `assessments`, and `limitations`.
- Invalid JSON or non-zero exit is converted to structured `error`.
