# TxRiskAgent

SignShield-style EVM pre-signature transaction risk analyzer.

The project analyzes wallet transaction JSON before signing. It decodes EVM calldata, classifies approvals/transfers/multicalls/unknown calls, enriches facts through optional real-world adapters, scores risk, and emits structured JSON plus Chinese plain-language warnings.
For ERC20 interactions it also builds a CertiK-style token risk profile covering owner privileges, honeypot/sell restrictions, tax controls, proxy/source transparency, bytecode signals, holder concentration, and LP lock facts when available.

## Airdrop Safety Track

This fork also includes an airdrop-focused demo track: **Airdrop Claim Pre-Signature Risk Agent**. The goal is to detect when a user thinks they are claiming an airdrop, but the pending wallet action actually grants an approval, Permit, NFT operator permission, transfer, bundled call, or opaque unknown-contract entrypoint.

Start here:

```text
docs/airdrop-security-cases.md
docs/airdrop-demo-storyline.md
```

Core airdrop demo fixtures:

```bash
mkdir -p output/risk-reports-airdrop
for fixture in \
  dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json \
  dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json \
  dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json \
  dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json \
  dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json \
  dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json
do
  uv run python skills/signshield-risk/scripts/analyze_evm_tx.py "$fixture" --output output/risk-reports-airdrop
done
```

If `uv` is not installed, the deterministic analyzer also runs with plain
Python:

```bash
mkdir -p output/risk-reports-airdrop
for fixture in \
  dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json \
  dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json \
  dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json \
  dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json \
  dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json \
  dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json
do
  python3 skills/signshield-risk/scripts/analyze_evm_tx.py "$fixture" --output output/risk-reports-airdrop
done
```

## Quick Start

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

Without `uv`:

```bash
python3 skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

Live enrichment mode:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --live --output output/risk-reports-live-smoke
```

Check bundled public EVM RPC endpoints:

```bash
uv run python skills/signshield-risk/scripts/check_public_rpc.py > output/public-rpc-check.json
```

Check Etherscan V2 enrichment without writing the key to disk:

```bash
ETHERSCAN_API_KEY=... uv run python skills/signshield-risk/scripts/check_etherscan.py
```

Subagent dry-run context:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --subagent dry-run --output output/risk-reports-subagent-context
```

## Live Adapters

The live mode supports:

- Sourcify/OpenChain + 4byte calldata selector resolution
- Tenderly transaction simulation
- Etherscan V2 / Blockscout contract reputation
- GoPlus token threat intelligence
- MetaMask eth-phishing-detect domain checks
- Public EVM RPC fallback for ERC20 metadata when `--live` is enabled and no explicit RPC is configured

Optional environment variables:

```bash
export TENDERLY_ACCOUNT_SLUG=...
export TENDERLY_PROJECT_SLUG=...
export TENDERLY_ACCESS_KEY=...
export ETHERSCAN_API_KEY=...
export BLOCKSCOUT_BASE_URL=...
export SIGNSSHIELD_RPC_URL=...
export SIGNSSHIELD_SUBAGENT_COMMAND=...
```

Missing credentials are reported in `evidence.limitations`; they do not abort analysis.
When `--live` is enabled, `SIGNSSHIELD_RPC_URL` or `--rpc-url` takes precedence. If neither is set, the analyzer probes bundled public HTTP RPC endpoints for the input `chainId` and records the chosen endpoint under `evidence.erc20TokenRisk.metadata.rpcStatus`. Use `--no-public-rpc-fallback` to keep live mode from using public RPC.
Etherscan keys must be supplied through `ETHERSCAN_API_KEY` or `--etherscan-api-key`; never commit them. The adapter records structured source, ABI, proxy, deployment, account, token-transfer, and provider-limitation facts under `evidence.contractReputation.etherscan` without storing full source code.

Subagent live mode uses `SIGNSSHIELD_SUBAGENT_COMMAND`. The command reads context JSON from stdin and writes assessment JSON to stdout.

## Validate

```bash
uv lock
uv run pytest -q
python3 -m py_compile $(find skills/signshield-risk/scripts -name '*.py' | sort)
```

Without `uv`, install the runtime/test dependencies in your active Python
environment and run the same checks directly:

```bash
python3 -m pip install requests pytest
python3 -m pytest -q
python3 -m py_compile $(find skills/signshield-risk/scripts -name '*.py' | sort)
```

## Skill

The Codex skill lives at:

```text
skills/signshield-risk/
```

Detailed adapter docs:

```text
skills/signshield-risk/references/external_adapters.md
```
