from __future__ import annotations

from copy import deepcopy
from typing import Any


DEFAULT_SUBAGENT_TASKS = [
    "source_semantic_privilege_review",
    "complex_honeypot_soft_rug_review",
    "protocol_domain_mismatch_review",
    "simulation_trace_attack_path_review",
    "unknown_or_multicall_intent_review",
]


def build_subagent_context(
    *,
    chain: dict[str, Any],
    token_address: str | None,
    origin: str | None,
    intent: dict[str, Any],
    decoded: dict[str, Any],
    token_profile: dict[str, Any],
    bytecode_scan: dict[str, Any],
    contract_reputation: dict[str, Any],
    threat_intel: dict[str, Any],
    simulation: dict[str, Any],
    deterministic_risk_factors: list[dict[str, Any]],
    provider_health: list[dict[str, Any]] | None = None,
    evidence_quality: dict[str, Any] | None = None,
    verdict_pre_subagent: dict[str, Any] | None = None,
    tasks: list[str] | None = None,
) -> dict[str, Any]:
    token_profile = token_profile if isinstance(token_profile, dict) else {}
    return {
        "schemaVersion": "signshield-subagent-context/v0.1",
        "tasks": tasks or DEFAULT_SUBAGENT_TASKS,
        "chain": chain,
        "token": {"address": token_address, "metadata": deepcopy(token_profile.get("metadata", {}))},
        "origin": origin,
        "intent": intent,
        "decodedCalldata": {
            "selector": decoded.get("selector"),
            "function": decoded.get("function"),
            "parameters": deepcopy(decoded.get("parameters", {})),
            "resolver": deepcopy(decoded.get("resolver")),
        },
        "tokenProfile": deepcopy(token_profile),
        "bytecodeScan": deepcopy(bytecode_scan),
        "contractReputation": _summarize_contract_reputation(contract_reputation),
        "threatIntel": _summarize_threat_intel(threat_intel),
        "simulation": _summarize_simulation(simulation),
        "providerHealth": deepcopy(provider_health or []),
        "evidenceQuality": deepcopy(evidence_quality or {}),
        "verdictPreSubagent": deepcopy(verdict_pre_subagent or {}),
        "deterministicRiskFactors": deepcopy(deterministic_risk_factors),
        "outputContract": {
            "status": "ok | skipped | error",
            "assessments": [
                {
                    "id": "source_semantic_privilege_review",
                    "conclusion": "string",
                    "severity": "LOW | MEDIUM | HIGH | CRITICAL",
                    "confidence": "LOW | MEDIUM | HIGH",
                    "evidenceRefs": ["evidence.erc20TokenRisk.tokenSecurity.mintable"],
                    "recommendedRiskFactors": [],
                }
            ],
            "limitations": [],
        },
    }


def _summarize_contract_reputation(contract_reputation: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": contract_reputation.get("status"),
        "address": contract_reputation.get("address"),
        "facts": contract_reputation.get("facts", []),
        "etherscan": contract_reputation.get("etherscan", {}),
        "blockscout": contract_reputation.get("blockscout", {}),
    }


def _summarize_threat_intel(threat_intel: dict[str, Any]) -> dict[str, Any]:
    providers = threat_intel.get("providers", {})
    return {
        "status": threat_intel.get("status"),
        "matches": threat_intel.get("matches", []),
        "providers": providers,
    }


def _summarize_simulation(simulation: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": simulation.get("status"),
        "provider": simulation.get("provider"),
        "facts": simulation.get("facts", []),
        "rawSummary": simulation.get("rawSummary", {}),
    }
