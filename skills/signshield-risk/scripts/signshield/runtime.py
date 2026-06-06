from __future__ import annotations

from typing import Any

from .types import AnalysisOptions, CalldataResolver, ContractReputationAdapter, SimulationAdapter, SubagentClient, ThreatIntelAdapter, TokenMetadataProvider


class DefenseRuntime:
    def __init__(
        self,
        options: AnalysisOptions | None = None,
        *,
        calldata_resolver: CalldataResolver | None = None,
        simulation_adapter: SimulationAdapter | None = None,
        contract_adapter: ContractReputationAdapter | None = None,
        threat_adapter: ThreatIntelAdapter | None = None,
        token_metadata_provider: TokenMetadataProvider | None = None,
        subagent_client: SubagentClient | None = None,
    ) -> None:
        self.options = options or AnalysisOptions()
        self.calldata_resolver = calldata_resolver
        self.simulation_adapter = simulation_adapter
        self.contract_adapter = contract_adapter
        self.threat_adapter = threat_adapter
        self.token_metadata_provider = token_metadata_provider
        self.subagent_client = subagent_client

    def analyze(self, payload: dict[str, Any], input_ref: str = "<memory>") -> dict[str, Any]:
        from .analyzer import analyze_transaction

        return analyze_transaction(
            payload,
            input_ref,
            options=self.options,
            calldata_resolver=self.calldata_resolver,
            simulation_adapter=self.simulation_adapter,
            contract_adapter=self.contract_adapter,
            threat_adapter=self.threat_adapter,
            token_metadata_provider=self.token_metadata_provider,
            subagent_client=self.subagent_client,
        )
