# SignShield Output Schema

The CLI returns compact user-facing JSON by default. Use `--output-format full` to return the full forensic evidence report.

## Compact CLI Output

```json
{
  "schemaVersion": "signshield-risk-compact/v0.1",
  "inputRef": "path-or-id",
  "verdict": {
    "riskLevel": "LOW | MEDIUM | HIGH | CRITICAL | UNSUPPORTED",
    "score": 0,
    "confidence": "LOW | MEDIUM | HIGH",
    "recommendedAction": "CONTINUE | CONTINUE_WITH_CAUTION | REDUCE_ALLOWANCE | USE_BURNER | REJECT | UNSUPPORTED"
  },
  "summary": "Deterministic plain-language summary.",
  "intent": {
    "category": "NATIVE_TRANSFER | ERC20_APPROVAL | NFT_APPROVAL | TOKEN_TRANSFER | MULTICALL | UNKNOWN_CONTRACT | UNSUPPORTED_CHAIN",
    "decodedFunction": "approve(address,uint256)"
  },
  "assetImpact": [],
  "keyRisks": [
    {
      "id": "large_or_unbounded_allowance",
      "severity": "HIGH",
      "title": "Short title",
      "description": "Specific user-facing explanation.",
      "sourceType": "deterministic_decode | live_provider | derived | subagent"
    }
  ],
  "reasoningTrace": [
    {
      "step": "decode | web_search | onchain_check | simulation | reputation | threat_intel | decision",
      "summary": "Short user-safe observation for UI display.",
      "evidenceRefs": ["evidence.calldata.function"]
    }
  ],
  "evidenceStatus": {
    "simulation": {"status": "ok", "provider": "tenderly", "factCount": 2},
    "contractReputation": {"status": "ok"},
    "threatIntel": {"status": "no_matches", "matchCount": 0}
  },
  "recommendation": "Plain-language next action.",
  "llmSummary": {
    "headline": "Short LLM-generated user headline.",
    "keyFindings": ["Concise finding based only on compact facts."],
    "userMessage": "One user-facing paragraph.",
    "nextAction": "Concise next action aligned with the deterministic verdict."
  },
  "summaryMeta": {
    "llm": {"status": "ok | skipped | error"}
  }
}
```

The LLM summary layer is enabled by default for compact CLI output. It never changes verdict fields or risk factors. If the LLM is unavailable, the CLI still writes deterministic compact JSON with `summaryMeta.llm.status = "error"`. Use `--summary-llm off` to skip the LLM layer.

## Full Evidence Output

The analyzer and `--output-format full` return one full JSON object per input transaction.

```json
{
  "schemaVersion": "signshield-risk/v0.2",
  "inputRef": "path-or-id",
  "verdict": {
    "riskLevel": "LOW | MEDIUM | HIGH | CRITICAL | UNSUPPORTED",
    "score": 0,
    "confidence": "LOW | MEDIUM | HIGH",
    "recommendedAction": "CONTINUE | CONTINUE_WITH_CAUTION | REDUCE_ALLOWANCE | USE_BURNER | REJECT | UNSUPPORTED"
  },
  "summary": "Plain-language user-facing summary.",
  "intent": {
    "category": "NATIVE_TRANSFER | ERC20_APPROVAL | NFT_APPROVAL | TOKEN_TRANSFER | MULTICALL | UNKNOWN_CONTRACT | UNSUPPORTED_CHAIN",
    "description": "Plain-language description of what the transaction appears to do.",
    "decodedFunction": "approve(address,uint256)"
  },
  "assetImpact": [
    {
      "type": "ERC20_APPROVAL | NATIVE_TRANSFER | TOKEN_TRANSFER | NFT_OPERATOR_APPROVAL",
      "asset": {"chainId": "eip155:1", "address": "0x...", "symbol": "ETH", "decimals": 18},
      "amount": {"raw": "0x0", "formatted": "0.0", "isUnlimited": false},
      "from": "0x...",
      "to": "0x...",
      "spender": "0x..."
    }
  ],
  "riskFactors": [
    {
      "id": "unlimited_erc20_approval",
      "domain": "technical | scam_phishing | compliance | uncertainty",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "score": 30,
      "title": "Short title",
      "description": "Specific evidence-based explanation.",
      "evidence": {}
    }
  ],
  "reasoningTrace": [
    {
      "step": "input | decode | web_search | onchain_check | simulation | reputation | threat_intel | decision",
      "summary": "Short user-safe observation. This is an audit trace, not private chain-of-thought.",
      "evidenceRefs": ["evidence.calldata.function"]
    }
  ],
  "evidence": {
    "calldata": {},
    "simulation": {
      "status": "ok | config_missing | error | not_run",
      "provider": "tenderly",
      "facts": [
        {
          "type": "asset_change | balance_change | approval_change | revert_or_error | call_trace_present",
          "walletDirection": "out | in | self | none",
          "amountRaw": "1000000000000000000",
          "amountFormatted": "1",
          "symbol": "ETH",
          "from": "0x...",
          "to": "0x..."
        }
      ],
      "rawSummary": {
        "id": "simulation-id",
        "status": true,
        "gasUsed": 21000,
        "assetChangeCount": 1,
        "balanceChangeCount": 0
      }
    },
    "contractReputation": {},
    "threatIntel": {},
    "erc20TokenRisk": {
      "tokenSecurity": {
        "sourceVerified": true,
        "isProxy": false,
        "implementationVerified": null,
        "ownershipRenounced": false,
        "hiddenOwner": false,
        "canRegainOwnership": false,
        "mintable": false,
        "blacklistEnabled": false,
        "whitelistEnabled": false,
        "taxMutable": false,
        "balanceMutable": false,
        "withdrawFunction": false,
        "selfdestructPresent": false,
        "externalCallPresent": false,
        "transferPausable": false,
        "transferCooldown": false
      },
      "marketControls": {
        "buyTaxBps": 0,
        "sellTaxBps": 0,
        "canBuy": true,
        "canSell": true,
        "cannotSellAll": false,
        "antiWhaleEnabled": false,
        "antiWhaleMutable": false
      },
      "holderAndLiquidity": {
        "majorHolderRatio": null,
        "top10HolderRatio": null,
        "lpLockedRatio": null,
        "topLpHolderRatio": null
      },
      "deployment": {
        "deployedAt": null,
        "ageDays": null,
        "deployer": null,
        "owner": null,
        "dexPair": null
      },
      "subagentAssessments": []
    },
    "limitations": []
  },
  "recommendation": "Plain-language next action."
}
```

Risk level thresholds:

- `LOW`: 0-24
- `MEDIUM`: 25-49
- `HIGH`: 50-74
- `CRITICAL`: 75+

Confidence should reflect fact quality. Deterministic decode plus direct fixtures can be `HIGH`; decode without simulation is usually `MEDIUM`; unknown selectors without simulation are `LOW`.

## Live Adapter Statuses

Adapters must not throw into the top-level CLI for expected integration problems. Use structured statuses:

- `ok`: Provider returned parseable data.
- `no_match` / `no_matches`: Provider returned data but no risk signal.
- `not_found`: Lookup completed without a selector or contract match.
- `config_missing`: Required API key/base URL/account setting is absent.
- `unsupported_chain`: Provider does not support the chain.
- `error`: HTTP, auth, rate-limit, or parse failure. Include a short `error`.
- `not_run`: Adapter was disabled because `--live` was not used.

## Subagent Harness

Subagent mode is controlled by CLI `--subagent off|dry-run|live`.

- `off`: no context is generated.
- `dry-run`: context is attached at `evidence.erc20TokenRisk.subagent.context`; no assessment changes verdict or risk factors.
- `live`: `SIGNSSHIELD_SUBAGENT_COMMAND` or `--subagent-command` must point to a command that reads context JSON from stdin and writes the required assessment JSON to stdout.

Subagent output is advisory. It may append `subagentAssessments` and recommended risk factors; it must not overwrite deterministic facts.
