from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any, Callable

from .adapters import (
    CombinedCalldataResolver,
    CompositeContractReputationAdapter,
    CompositeThreatIntelAdapter,
    FourByteDirectoryResolver,
    SourcifyOpenChainResolver,
    TenderlySimulationAdapter,
)
from .adapters.http import HttpClient
from .decode import decode_calldata
from .contract_bytecode_scanner import scan_contract_bytecode
from .token_metadata import TokenMetadataResolver
from .token_security_normalizer import build_erc20_token_risk_profile
from .types import AnalysisOptions, CalldataResolver, ContractReputationAdapter, SimulationAdapter, ThreatIntelAdapter, TokenMetadataProvider


@dataclass
class EvidenceBundle:
    decoded: dict[str, Any]
    simulation: dict[str, Any]
    contract_reputation: dict[str, Any]
    threat_intel: dict[str, Any]
    token_metadata: dict[str, Any]
    bytecode_scan: dict[str, Any]
    erc20_profile: dict[str, Any] | None
    provider_health: list[dict[str, Any]]
    evidence_quality: dict[str, Any]


class EvidenceOrchestrator:
    def __init__(
        self,
        options: AnalysisOptions,
        *,
        calldata_resolver: CalldataResolver | None = None,
        simulation_adapter: SimulationAdapter | None = None,
        contract_adapter: ContractReputationAdapter | None = None,
        threat_adapter: ThreatIntelAdapter | None = None,
        token_metadata_provider: TokenMetadataProvider | None = None,
    ) -> None:
        self.options = options
        self.mode = resolve_mode(options)
        self.calldata_resolver = calldata_resolver
        self.simulation_adapter = simulation_adapter
        self.contract_adapter = contract_adapter
        self.threat_adapter = threat_adapter
        self.token_metadata_provider = token_metadata_provider
        if self.mode != "offline":
            client = HttpClient(timeout=options.timeout)
            self.calldata_resolver = self.calldata_resolver or CombinedCalldataResolver([SourcifyOpenChainResolver(client=client), FourByteDirectoryResolver(client=client)])
            self.simulation_adapter = self.simulation_adapter or TenderlySimulationAdapter(options.tenderly_account, options.tenderly_project, options.tenderly_access_key, client=client)
            self.contract_adapter = self.contract_adapter or CompositeContractReputationAdapter(options.etherscan_api_key, options.blockscout_base_url, client=client)
            self.threat_adapter = self.threat_adapter or CompositeThreatIntelAdapter(options.goplus_base_url, options.metamask_config_url, client=client)
        self.token_metadata_provider = self.token_metadata_provider or TokenMetadataResolver(
            options.rpc_url,
            client=HttpClient(timeout=options.timeout),
            public_fallback=self.mode != "offline" and options.public_rpc_fallback,
        )

    def collect(
        self,
        *,
        chain_id: int,
        data: str | None,
        tx: dict[str, Any],
        to_addr: str | None,
        addresses: list[str],
        origin: str | None,
        erc20_token_address: str | None,
    ) -> EvidenceBundle:
        provider_health: list[dict[str, Any]] = []
        decoded, decode_health = self._call_provider(
            "calldata_resolver",
            "live_provider" if self.calldata_resolver else "deterministic_decode",
            lambda: decode_calldata(data, self.calldata_resolver),
        )
        provider_health.append(decode_health)

        simulation = {"status": "not_run", "facts": []}
        if self.simulation_adapter:
            simulation, health = self._call_provider("simulation", "live_provider", lambda: self.simulation_adapter.simulate(chain_id, tx))
            provider_health.append(health)
        else:
            provider_health.append(_health("simulation", "not_run", "live_provider", participated=False))

        contract_reputation = {"status": "not_run", "facts": []}
        if self.contract_adapter:
            contract_reputation, health = self._call_provider("contract_reputation", "live_provider", lambda: self.contract_adapter.inspect(chain_id, to_addr))
            provider_health.append(health)
        else:
            provider_health.append(_health("contract_reputation", "not_run", "live_provider", participated=False))

        threat_intel = {"status": "not_run", "matches": []}
        if self.threat_adapter:
            threat_intel, health = self._call_provider("threat_intel", "live_provider", lambda: self.threat_adapter.inspect(chain_id, addresses, origin))
            provider_health.append(health)
        else:
            provider_health.append(_health("threat_intel", "not_run", "live_provider", participated=False))

        token_metadata: dict[str, Any] = {}
        bytecode_scan: dict[str, Any] = {"status": "not_applicable", "signals": {}}
        erc20_profile: dict[str, Any] | None = None
        if erc20_token_address:
            token_metadata, health = self._call_provider(
                "token_metadata",
                "live_provider" if self.mode != "offline" else "fixture",
                lambda: self.token_metadata_provider.metadata(chain_id, erc20_token_address, contract_reputation),
            )
            provider_health.append(health)
            bytecode_scan, health = self._call_provider(
                "bytecode_scan",
                "fixture" if self.mode == "offline" else "derived",
                lambda: scan_contract_bytecode(chain_id, erc20_token_address, contract_reputation),
            )
            provider_health.append(health)
            erc20_profile = build_erc20_token_risk_profile(
                chain_id,
                erc20_token_address,
                token_metadata=token_metadata,
                contract_reputation=contract_reputation,
                threat_intel=threat_intel,
                bytecode_scan=bytecode_scan,
            )

        evidence_quality = build_evidence_quality(self.mode, provider_health, erc20_profile)
        return EvidenceBundle(
            decoded=decoded,
            simulation=simulation,
            contract_reputation=contract_reputation,
            threat_intel=threat_intel,
            token_metadata=token_metadata,
            bytecode_scan=bytecode_scan,
            erc20_profile=erc20_profile,
            provider_health=provider_health,
            evidence_quality=evidence_quality,
        )

    def _call_provider(self, name: str, source_type: str, fn: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        started = perf_counter()
        try:
            result = fn()
        except Exception as exc:
            latency = round((perf_counter() - started) * 1000)
            return {"status": "error", "error": str(exc)}, _health(name, "error", source_type, latency_ms=latency, error=str(exc), participated=False)
        latency = round((perf_counter() - started) * 1000)
        status = str(result.get("status") or "ok") if isinstance(result, dict) else "unexpected_response"
        participated = status not in {"not_run", "config_missing", "error", "unsupported_chain", "no_address"}
        return result, _health(name, status, source_type, latency_ms=latency, participated=participated)


def resolve_mode(options: AnalysisOptions) -> str:
    if options.mode:
        return options.mode
    return "live-best-effort" if options.live else "offline"


def build_evidence_quality(mode: str, provider_health: list[dict[str, Any]], erc20_profile: dict[str, Any] | None) -> dict[str, Any]:
    live_sources = [item["provider"] for item in provider_health if item.get("participatedInDecision") and item.get("sourceType") == "live_provider"]
    fixture_sources = []
    if isinstance(erc20_profile, dict):
        fixture_sources = [source for source in erc20_profile.get("sources", []) if "fixture" in str(source)]
    blocking = [
        item["provider"]
        for item in provider_health
        if item.get("status") in {"config_missing", "error", "unavailable"} and item.get("provider") in {"simulation", "contract_reputation"}
    ]
    minimum_met = bool(live_sources) or mode == "offline"
    return {
        "mode": mode,
        "liveSourcesUsed": live_sources,
        "fixtureSourcesUsed": fixture_sources,
        "minimumEvidenceMet": minimum_met,
        "decisionReliability": "HIGH" if len(live_sources) >= 2 else "MEDIUM" if live_sources else "LOW",
        "blockingProviders": blocking,
    }


def _health(
    provider: str,
    status: str,
    source_type: str,
    *,
    latency_ms: int | None = None,
    error: str | None = None,
    participated: bool = False,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "provider": provider,
        "status": status,
        "sourceType": source_type,
        "participatedInDecision": participated,
    }
    if latency_ms is not None:
        item["latencyMs"] = latency_ms
    if error:
        item["errorSummary"] = error[:300]
    return item
