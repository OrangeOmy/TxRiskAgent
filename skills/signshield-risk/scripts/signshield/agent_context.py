from __future__ import annotations

from copy import deepcopy
from typing import Any

from .decode import decode_calldata
from .decision import build_decision
from .evidence import EvidenceOrchestrator, resolve_mode
from .rules import RuleContext, default_rule_engine
from .types import (
    AddressProfileProvider,
    AnalysisOptions,
    CalldataResolver,
    ContractReputationAdapter,
    SimulationAdapter,
    ThreatIntelAdapter,
    TokenMetadataProvider,
)
from .utils import hex_to_int, normalize_address, normalize_chain


PRIMITIVE_CATALOG: list[dict[str, Any]] = [
    {
        "name": "wallet_transaction",
        "category": "wallet_input",
        "fields": ["chainId", "transactionOrigin", "from", "to", "value", "data", "gas"],
        "description": "Raw pre-signature wallet transaction request.",
    },
    {
        "name": "calldata_decode",
        "category": "decode",
        "sources": ["local_selector_table", "sourcify_openchain", "4byte_directory"],
        "description": "Function selector, ABI signature, and decoded standard parameters.",
    },
    {
        "name": "address_profile",
        "category": "rpc",
        "sources": ["explicit_rpc", "public_rpc_fallback"],
        "description": "Recipient account type, contract bytecode presence, and EIP-7702 delegation facts.",
    },
    {
        "name": "simulation",
        "category": "simulation",
        "sources": ["tenderly"],
        "description": "Wallet-relative asset changes, approval changes, revert facts, and call-trace presence.",
    },
    {
        "name": "contract_reputation",
        "category": "contract_reputation",
        "sources": ["etherscan", "blockscout"],
        "description": "Source verification, proxy implementation, deployment, labels, and source/ABI security signals.",
    },
    {
        "name": "threat_intel",
        "category": "threat_intel",
        "sources": ["goplus", "metamask_eth_phishing_detect"],
        "description": "Address, token, and origin-domain threat intelligence matches.",
    },
    {
        "name": "erc20_token_profile",
        "category": "derived_token_risk",
        "sources": ["token_metadata", "contract_reputation", "goplus", "bytecode_scan"],
        "description": "ERC20 owner privileges, transfer controls, honeypot/tax flags, proxy status, deployment, holder, and liquidity facts.",
    },
    {
        "name": "deterministic_risk_signals",
        "category": "baseline_rules",
        "description": "Rule-derived candidate risk signals from observed facts; use as evidence, not as a mandatory final verdict.",
    },
]


def build_agent_primitive_context(
    payload: dict[str, Any],
    input_ref: str = "<memory>",
    *,
    options: AnalysisOptions | None = None,
    calldata_resolver: CalldataResolver | None = None,
    simulation_adapter: SimulationAdapter | None = None,
    contract_adapter: ContractReputationAdapter | None = None,
    threat_adapter: ThreatIntelAdapter | None = None,
    address_profile_provider: AddressProfileProvider | None = None,
    token_metadata_provider: TokenMetadataProvider | None = None,
) -> dict[str, Any]:
    from .analyzer import (
        classify_intent,
        collect_addresses,
        erc20_token_target,
        normalize_transaction_payload,
        unsupported_result,
    )

    options = options or AnalysisOptions(agent_loop="off")
    mode = resolve_mode(options)
    allow_fixture_risk = options.allow_fixture_risk and mode != "production"

    tx = normalize_transaction_payload(payload)
    origin = payload.get("transactionOrigin") or payload.get("origin")
    chain = normalize_chain(payload.get("chainId") or tx.get("chainId"))
    if not chain.supported:
        return {
            "schemaVersion": "signshield-agent-primitives/v0.1",
            "inputRef": input_ref,
            "primitiveCatalog": deepcopy(PRIMITIVE_CATALOG),
            "unsupportedResult": unsupported_result(input_ref, chain.raw),
            "outputContract": agent_output_contract(),
        }

    from_addr = normalize_address(tx.get("from"))
    to_addr = normalize_address(tx.get("to"))
    data = tx.get("data") if isinstance(tx.get("data"), str) else "0x"
    value_wei = hex_to_int(tx.get("value"), 0)
    initial_decoded = decode_calldata(data, calldata_resolver)
    initial_category, _ = classify_intent(initial_decoded, value_wei)
    addresses = collect_addresses(from_addr, to_addr, initial_decoded)
    erc20_token_address = erc20_token_target(initial_category, to_addr)

    orchestrator = EvidenceOrchestrator(
        options,
        calldata_resolver=calldata_resolver,
        simulation_adapter=simulation_adapter,
        contract_adapter=contract_adapter,
        threat_adapter=threat_adapter,
        address_profile_provider=address_profile_provider,
        token_metadata_provider=token_metadata_provider,
    )
    evidence = orchestrator.collect(
        chain_id=chain.chain_id,
        data=data,
        tx=tx,
        to_addr=to_addr,
        addresses=addresses,
        origin=origin,
        erc20_token_address=erc20_token_address,
    )

    decoded = evidence.decoded
    category, intent_description = classify_intent(decoded, value_wei)
    if erc20_token_address is None:
        erc20_token_address = erc20_token_target(category, to_addr)

    intent = {"category": category, "description": intent_description, "decodedFunction": decoded.get("function")}
    chain_evidence = {"raw": chain.raw, "chainId": chain.chain_id, "caip2": chain.caip2, "name": chain.name}
    rule_context = RuleContext(
        mode=mode,
        chain=chain_evidence,
        tx=tx,
        origin=origin,
        from_addr=from_addr,
        to_addr=to_addr,
        value_wei=value_wei,
        decoded=decoded,
        intent=intent,
        simulation=evidence.simulation,
        contract_reputation=evidence.contract_reputation,
        threat_intel=evidence.threat_intel,
        address_profile=evidence.address_profile,
        erc20_profile=evidence.erc20_profile,
        provider_health=evidence.provider_health,
        evidence_quality=evidence.evidence_quality,
        allow_fixture_risk=allow_fixture_risk,
    )
    rule_result = default_rule_engine().evaluate(rule_context)
    preliminary_verdict = build_decision(
        category=category,
        decoded=decoded,
        simulation=evidence.simulation,
        contract_reputation=evidence.contract_reputation,
        threat_intel=evidence.threat_intel,
        factors=rule_result.risk_factors,
        evidence_quality=evidence.evidence_quality,
        mode=mode,
    )

    limitations = []
    if evidence.simulation.get("status") in {"not_run", "config_missing"}:
        limitations.append("No live transaction simulation was executed.")
    if evidence.contract_reputation.get("status") in {"not_run", "config_missing", "limited"}:
        limitations.append("Live source verification, proxy, deployment age, or label data may be incomplete.")
    if evidence.threat_intel.get("status") in {"not_run", "config_missing"}:
        limitations.append("No live third-party threat intelligence was queried.")
    limitations.extend(rule_result.limitations)

    return {
        "schemaVersion": "signshield-agent-primitives/v0.1",
        "inputRef": input_ref,
        "runtimeMode": mode,
        "primitiveCatalog": deepcopy(PRIMITIVE_CATALOG),
        "normalizedInput": {
            "chain": chain_evidence,
            "origin": origin,
            "transaction": tx,
            "from": from_addr,
            "to": to_addr,
            "data": data,
            "valueWei": str(value_wei),
            "observedAddresses": addresses,
            "erc20TokenAddress": erc20_token_address,
        },
        "intent": intent,
        "assetImpactCandidates": rule_result.asset_impacts,
        "deterministicRiskSignals": rule_result.risk_factors,
        "evidence": {
            "calldata": decoded,
            "addressProfile": evidence.address_profile,
            "simulation": evidence.simulation,
            "contractReputation": evidence.contract_reputation,
            "threatIntel": evidence.threat_intel,
            "erc20TokenRisk": evidence.erc20_profile,
            "providerHealth": evidence.provider_health,
            "evidenceQuality": evidence.evidence_quality,
            "limitations": limitations,
        },
        "preliminaryVerdict": preliminary_verdict,
        "outputContract": agent_output_contract(),
    }


def agent_output_contract() -> dict[str, Any]:
    return {
        "schemaVersion": "signshield-risk/v0.2",
        "requiredTopLevelFields": [
            "schemaVersion",
            "inputRef",
            "verdict",
            "summary",
            "intent",
            "assetImpact",
            "riskFactors",
            "reasoningTrace",
            "evidence",
            "recommendation",
        ],
        "verdict": {
            "riskLevel": "LOW | MEDIUM | HIGH | CRITICAL | UNSUPPORTED",
            "score": "integer 0..100",
            "confidence": "LOW | MEDIUM | HIGH",
            "recommendedAction": "CONTINUE | CONTINUE_WITH_CAUTION | REDUCE_ALLOWANCE | USE_BURNER | REVIEW_OR_REJECT | REJECT | UNSUPPORTED",
        },
        "riskFactor": {
            "id": "stable snake_case id",
            "domain": "technical | scam_phishing | compliance | uncertainty",
            "severity": "LOW | MEDIUM | HIGH | CRITICAL",
            "score": "integer 0..100 contribution",
            "title": "short Chinese title",
            "description": "specific evidence-based Chinese explanation",
            "evidence": "object containing only facts present in the primitive context",
            "sourceType": "agent_loop",
        },
        "reasoningTraceItem": {
            "step": "input | decode | web_search | onchain_check | simulation | reputation | threat_intel | decision",
            "summary": "short user-safe observation for UI display",
            "evidenceRefs": ["dot.path.into.report"],
        },
    }
