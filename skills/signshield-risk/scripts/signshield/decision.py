from __future__ import annotations

from typing import Any

from .scoring import recommended_action
from .utils import risk_level


GUARDED_CATEGORIES = {"MULTICALL", "UNKNOWN_CONTRACT"}
GUARDED_FACTOR_IDS = {"large_or_unbounded_allowance", "nft_collection_wide_approval"}


def build_decision(
    *,
    category: str,
    decoded: dict[str, Any],
    simulation: dict[str, Any],
    contract_reputation: dict[str, Any],
    threat_intel: dict[str, Any],
    factors: list[dict[str, Any]],
    evidence_quality: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    score = min(sum(int(factor["score"]) for factor in factors), 100)
    level = risk_level(score)
    action = recommended_action(level, factors)
    confidence = confidence_for(category, decoded, simulation, contract_reputation, threat_intel, factors)
    gate = evidence_gate(category, factors, simulation, contract_reputation, evidence_quality, mode)
    if gate["guarded"]:
        confidence = "LOW" if confidence == "LOW" else "MEDIUM"
        if action in {"CONTINUE", "CONTINUE_WITH_CAUTION", "REDUCE_ALLOWANCE"}:
            action = "REVIEW_OR_REJECT"
    return {
        "riskLevel": level,
        "score": score,
        "confidence": confidence,
        "recommendedAction": action,
        "evidenceGate": gate,
    }


def evidence_gate(
    category: str,
    factors: list[dict[str, Any]],
    simulation: dict[str, Any],
    contract_reputation: dict[str, Any],
    evidence_quality: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    factor_ids = {factor["id"] for factor in factors}
    requires_live = category in GUARDED_CATEGORIES or bool(factor_ids & GUARDED_FACTOR_IDS)
    has_simulation = simulation.get("status") == "ok"
    has_contract = _has_live_contract_reputation(contract_reputation)
    guarded = mode == "production" and requires_live and not (has_simulation or has_contract)
    reasons = []
    if guarded:
        reasons.append("Minimum live evidence was not met for a high-uncertainty transaction.")
    return {
        "guarded": guarded,
        "requiresLiveEvidence": requires_live,
        "hasSimulation": has_simulation,
        "hasContractReputation": has_contract,
        "reasons": reasons,
    }


def _has_live_contract_reputation(contract_reputation: dict[str, Any]) -> bool:
    for key in ("etherscan", "blockscout"):
        source = contract_reputation.get(key)
        if isinstance(source, dict) and source.get("status") == "ok":
            return True
    return False


def confidence_for(category: str, decoded: dict[str, Any], simulation: dict[str, Any], contract_rep: dict[str, Any], threat_intel: dict[str, Any], factors: list[dict[str, Any]]) -> str:
    factor_ids = {factor["id"] for factor in factors}
    if "known_malicious_spender" in factor_ids or threat_intel.get("matches"):
        return "HIGH"
    if simulation.get("status") == "ok" and decoded.get("function"):
        return "HIGH"
    if category in {"NATIVE_TRANSFER", "ERC20_APPROVAL", "NFT_APPROVAL", "TOKEN_TRANSFER"} and decoded.get("function") is not None or category == "NATIVE_TRANSFER":
        return "HIGH"
    if contract_rep.get("status") == "ok":
        return "MEDIUM"
    return "LOW"
