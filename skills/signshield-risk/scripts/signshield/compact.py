from __future__ import annotations

from typing import Any


COMPACT_SCHEMA_VERSION = "signshield-risk-compact/v0.1"
MAX_KEY_RISKS = 5
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def compact_report(full_result: dict[str, Any]) -> dict[str, Any]:
    """Build a user-facing report without full provider/debug evidence."""
    evidence = full_result.get("evidence") if isinstance(full_result.get("evidence"), dict) else {}
    report = {
        "schemaVersion": COMPACT_SCHEMA_VERSION,
        "inputRef": full_result.get("inputRef"),
        "verdict": _compact_verdict(full_result.get("verdict")),
        "summary": full_result.get("summary"),
        "intent": _compact_intent(full_result.get("intent")),
        "assetImpact": [_compact_asset_impact(item) for item in _as_list(full_result.get("assetImpact"))],
        "keyRisks": _key_risks(_as_list(full_result.get("riskFactors"))),
        "evidenceStatus": _evidence_status(evidence),
        "recommendation": full_result.get("recommendation"),
        "summaryMeta": {"llm": {"status": "not_run"}},
    }
    if not report["assetImpact"]:
        report["assetImpact"] = []
    return report


def _compact_verdict(verdict: Any) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        return {}
    return {key: verdict.get(key) for key in ("riskLevel", "score", "confidence", "recommendedAction") if verdict.get(key) is not None}


def _compact_intent(intent: Any) -> dict[str, Any]:
    if not isinstance(intent, dict):
        return {}
    return {key: intent.get(key) for key in ("category", "decodedFunction") if intent.get(key) is not None}


def _compact_asset_impact(impact: Any) -> dict[str, Any]:
    if not isinstance(impact, dict):
        return {}
    compact = {
        "type": impact.get("type"),
        "asset": _compact_asset(impact.get("asset")),
        "amount": _compact_amount(impact.get("amount")),
    }
    for key in ("from", "to", "spender", "operator"):
        if impact.get(key) is not None:
            compact[key] = impact.get(key)
    return {key: value for key, value in compact.items() if value not in (None, {}, [])}


def _compact_asset(asset: Any) -> dict[str, Any]:
    if not isinstance(asset, dict):
        return {}
    return {key: asset.get(key) for key in ("chainId", "address", "symbol", "name", "decimals") if asset.get(key) is not None}


def _compact_amount(amount: Any) -> dict[str, Any]:
    if not isinstance(amount, dict):
        return {}
    return {key: amount.get(key) for key in ("formatted", "isUnlimited", "raw") if amount.get(key) is not None}


def _key_risks(risk_factors: list[Any]) -> list[dict[str, Any]]:
    factors = [factor for factor in risk_factors if isinstance(factor, dict)]
    meaningful = [factor for factor in factors if factor.get("severity") != "LOW"]
    meaningful.sort(key=lambda factor: (-SEVERITY_RANK.get(str(factor.get("severity")), 0), -int(factor.get("score") or 0)))
    result = []
    for factor in meaningful[:MAX_KEY_RISKS]:
        result.append(
            {
                key: factor.get(key)
                for key in ("id", "severity", "title", "description", "sourceType")
                if factor.get(key) is not None
            }
        )
    return result


def _evidence_status(evidence: dict[str, Any]) -> dict[str, Any]:
    status = {
        "simulation": _provider_status(evidence.get("simulation")),
        "contractReputation": _provider_status(evidence.get("contractReputation")),
        "threatIntel": _provider_status(evidence.get("threatIntel")),
    }
    provider_health = evidence.get("providerHealth")
    if isinstance(provider_health, list):
        status["providerHealth"] = [_health_item(item) for item in provider_health if isinstance(item, dict)]
    limitations = evidence.get("limitations")
    if isinstance(limitations, list) and limitations:
        status["limitations"] = [str(item) for item in limitations[:5]]
    return status


def _provider_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "missing"}
    result = {key: value.get(key) for key in ("status", "provider") if value.get(key) is not None}
    if value.get("error") is not None:
        result["error"] = str(value.get("error"))[:300]
    facts = value.get("facts")
    if isinstance(facts, list):
        result["factCount"] = len(facts)
    matches = value.get("matches")
    if isinstance(matches, list):
        result["matchCount"] = len(matches)
    return result or {"status": "missing"}


def _health_item(item: dict[str, Any]) -> dict[str, Any]:
    return {key: item.get(key) for key in ("provider", "status", "reason") if item.get(key) is not None}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
