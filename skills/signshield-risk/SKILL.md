---
name: signshield-risk
description: Analyze EVM pre-signature transaction JSON for SignShield-style wallet risk explanations, especially airdrop claim flows where a user may think they are claiming rewards but actually signs an approval, Permit, NFT operator permission, transfer, multicall, or unknown contract call.
---

# SignShield Risk

## Overview

Produce a SignShield risk structure for EVM transaction requests before a user signs. Keep the workflow fact-first: decode and normalize transaction facts, apply deterministic rules, then explain those facts in natural language.

This skill is EVM-only. For non-`eip155` chains, return an unsupported result instead of attempting chain-specific analysis.

## Airdrop Claim Safety Focus

Use this narrower flow when the user, origin, fixture name, page context, or goal mentions `claim`, `airdrop`, `rewards`, `gasless`, `verify`, `mint free`, or wallet verification.

The goal is not to prove whether an airdrop exists. The goal is to decide what the pending wallet action actually does before signing:

- Does a claimed `claim` actually call `approve(address,uint256)`?
- Does a claimed `gasless claim` actually create a Permit or Permit2-style spending authorization?
- Does a claimed NFT verification actually call `setApprovalForAll(address,bool)`?
- Does a claim bundle hide approvals, transfers, or unknown calls behind `multicall` or router-style `execute`?
- Is the selector or contract opaque enough that the system should warn about missing evidence instead of implying safety?

For airdrop-like flows, always explain the mismatch between the user's likely expectation and the decoded intent when facts support it. Prefer language such as "This is not just a claim" or "Gasless does not mean harmless" when the structured facts show approval or Permit behavior.

## Quick Start

Run the analyzer from a project that has `uv`:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --output output/risk-reports
```

For a single file:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx/example.json
```

Default mode is deterministic and offline except for local fixtures. Use `--live` to enable real-world adapters:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --live --output output/risk-reports-live
```

Live adapters are best-effort. Missing API keys or provider failures are written into `evidence` and `limitations`; they should not crash the analysis.
When `--live` is enabled and no `--rpc-url`/`SIGNSSHIELD_RPC_URL` is configured, the analyzer probes bundled public EVM HTTP RPC endpoints for the transaction chain and falls back to the first chain-matching endpoint. The selected endpoint and probe attempts are recorded under `evidence.erc20TokenRisk.metadata.rpcStatus`. Use `--no-public-rpc-fallback` to disable this behavior.

Public RPC availability can be checked independently:

```bash
uv run python skills/signshield-risk/scripts/check_public_rpc.py > output/public-rpc-check.json
```

Etherscan V2 enrichment uses only runtime configuration. Do not write API keys into files:

```bash
ETHERSCAN_API_KEY=... uv run python skills/signshield-risk/scripts/check_etherscan.py
```

ERC20 semantic review can be enabled separately:

```bash
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --subagent dry-run
uv run python skills/signshield-risk/scripts/analyze_evm_tx.py dump-tx --subagent live --subagent-command ./agent-command
```

## Workflow

1. Normalize input.
   Accept either `chainId` plus `transaction`, or a flat transaction-like object. Convert `eip155:<id>` into an EVM chain id. Validate addresses and hex values.

2. Build the fact layer.
   Decode calldata selectors and standard ABI parameters. Extract native value, token/spender/operator/amount, and origin. For ERC20 interactions, build `evidence.erc20TokenRisk` from token metadata, token security facts, contract reputation, bytecode scan signals, holder/liquidity facts, and optional subagent assessments. In live mode, enrich facts through Sourcify/OpenChain + 4byte, Tenderly, Etherscan V2/Blockscout, GoPlus, and MetaMask eth-phishing-detect. Etherscan facts should remain summarized: include source/ABI/proxy/deployment/account/token-transfer/security-signal fields, not full source code.

3. Classify intent.
   Route to one primary category: `NATIVE_TRANSFER`, `ERC20_APPROVAL`, `NFT_APPROVAL`, `TOKEN_TRANSFER`, `MULTICALL`, `UNKNOWN_CONTRACT`, or `UNSUPPORTED_CHAIN`.

4. Apply the airdrop overlay when context is claim-like.
   Compare the user-facing claim context with the actual decoded branch. Treat `ERC20_APPROVAL`, Permit/Permit2, `NFT_APPROVAL`, `TOKEN_TRANSFER`, and opaque `MULTICALL`/`UNKNOWN_CONTRACT` as potential claim-intent mismatches. If the current output schema does not yet expose explicit `claimedIntent` or `intentMismatch` fields, describe the mismatch in `summary`, `riskFactors`, and `recommendation`.

5. Score and separate risk domains.
   Keep technical risk, scam/phishing risk, and compliance risk as separate lists and score contributions. Never conflate OFAC/compliance hits with contract exploit evidence.

6. Explain only structured facts.
   Generate summaries and recommendations from decoded facts, simulation facts, reputation facts, and limitations. Do not invent source verification, deployment age, labels, or simulation outcomes if they were not observed.

## Risk Branches

- `ERC20_APPROVAL`: detect `approve(address,uint256)`, permit variants, Permit2, unlimited or overlarge allowances, unknown or malicious spenders, and proxy reputation.
- `NFT_APPROVAL`: detect `setApprovalForAll(address,bool)` and mark collection-wide operator permissions as high risk when enabled.
- `NATIVE_TRANSFER`: detect empty calldata with native value. Flag burn/dead addresses, suspicious recipients, and large value transfers.
- `TOKEN_TRANSFER`: detect `transfer` and `transferFrom`; use simulation facts when available to describe actual asset movement.
- `MULTICALL`: detect `multicall`, `execute`, or arbitrary-call selectors; recursively decode embedded calls when the implementation adds support.
- `UNKNOWN_CONTRACT`: use when selector is unknown, source is unavailable, proxy implementation is unverified, or facts are insufficient.
- `UNSUPPORTED_CHAIN`: use for any non-EVM chain.

## Airdrop Demo Corpus

The core airdrop demo fixtures are:

- `dump-tx/2026-06-03T00-01-00-000Z-erc20-unlimited-approval-phishing.json`: fake claim page asks for unlimited ERC20 approval.
- `dump-tx/2026-06-03T00-03-00-000Z-eip2612-permit-unlimited-drainer.json`: gasless claim creates a Permit approval.
- `dump-tx/2026-06-03T00-04-00-000Z-nft-setapprovalforall-fake-airdrop.json`: NFT airdrop verification grants collection-wide operator approval.
- `dump-tx/2026-06-03T00-09-00-000Z-multicall-hidden-approval-and-transfer.json`: claim bundle hides approval and transfer payloads.
- `dump-tx/2026-06-03T00-11-00-000Z-universal-router-execute-permit2-style-drain.json`: router/Permit2-style claim bundle.
- `dump-tx/2026-06-03T00-12-00-000Z-unknown-claim-rewards-selector.json`: claim-like unknown selector.

Use `docs/airdrop-security-cases.md` for the core and extended case library,
including adjacent excessive-approval, revoke-control, direct-outflow,
`transferFrom`, deadline-multicall, address-poisoning, and native-drainer
fixtures. Use `docs/airdrop-demo-storyline.md` for the hackathon presentation
sequence.

## Output Contract

Return JSON compatible with `references/output_schema.md`. Every result should include:

- `verdict`: risk level, score, confidence, recommended action.
- `intent`: primary category and natural-language description.
- `assetImpact`: assets, permissions, or balances affected.
- `riskFactors`: concrete factors with severity, domain, score contribution, and evidence.
- `evidence`: decoded calldata, simulation placeholder, contract reputation, threat intel, ERC20 token risk profile when applicable, and limitations.
- `summary` and `recommendation`: user-facing Chinese explanations in this prototype.

## References

- Read `references/risk_branches.md` when changing branch logic.
- Read `references/output_schema.md` when changing JSON fields.
- Read `references/external_adapters.md` when changing live provider integrations.
- Read `docs/airdrop-security-cases.md` when changing airdrop claim, Permit, NFT approval, multicall, or unknown-claim behavior.
- Read `docs/airdrop-demo-storyline.md` when preparing or changing the hackathon demo script.
- Read `dump-tx/certik-token-scan-erc20-risk-summary.md` when changing ERC20 token-risk profile fields or CertiK-style scoring rules.
- Read `ACKNOWLEDGEMENTS.md` and linked research notes when changing ERC20 token-risk profile rules.
- Use `scripts/analyze_evm_tx.py` as the deterministic baseline implementation.

## Validation

```bash
uv lock
uv run pytest -q
python3 -m py_compile $(find skills/signshield-risk/scripts -name '*.py' | sort)
uv run --with pyyaml python /Users/lihangzhe/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/signshield-risk
```
