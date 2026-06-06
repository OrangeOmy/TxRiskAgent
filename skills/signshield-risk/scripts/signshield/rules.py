from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class RuleContext:
    mode: str
    chain: dict[str, Any]
    tx: dict[str, Any]
    origin: str | None
    from_addr: str | None
    to_addr: str | None
    value_wei: int
    decoded: dict[str, Any]
    intent: dict[str, Any]
    simulation: dict[str, Any]
    contract_reputation: dict[str, Any]
    threat_intel: dict[str, Any]
    address_profile: dict[str, Any] | None
    erc20_profile: dict[str, Any] | None
    provider_health: list[dict[str, Any]]
    evidence_quality: dict[str, Any]
    allow_fixture_risk: bool = True


@dataclass
class RuleResult:
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    asset_impacts: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RiskRule:
    id: str
    category: str
    enabled_modes: tuple[str, ...]
    evaluate_fn: Callable[[RuleContext], RuleResult]

    def evaluate(self, context: RuleContext) -> RuleResult:
        if context.mode not in self.enabled_modes:
            return RuleResult()
        return self.evaluate_fn(context)


class RuleEngine:
    def __init__(self, rules: list[RiskRule]) -> None:
        self.rules = rules

    def evaluate(self, context: RuleContext) -> RuleResult:
        merged = RuleResult()
        seen_factor_ids: set[str] = set()
        for rule in self.rules:
            try:
                result = rule.evaluate(context)
            except Exception as exc:
                merged.limitations.append(f"Rule {rule.id} failed: {exc}")
                continue
            for impact in result.asset_impacts:
                merged.asset_impacts.append(impact)
            for factor in result.risk_factors:
                factor_id = factor.get("id")
                if factor_id and factor_id in seen_factor_ids:
                    continue
                if factor_id:
                    seen_factor_ids.add(str(factor_id))
                merged.risk_factors.append(factor)
            merged.limitations.extend(result.limitations)
        return merged


def default_rule_engine() -> RuleEngine:
    from . import analyzer as legacy
    from .erc20_scoring import apply_erc20_token_profile_rules

    modes = ("offline", "live-best-effort", "production")

    def branch_rules(context: RuleContext) -> RuleResult:
        factors: list[dict[str, Any]] = []
        impacts: list[dict[str, Any]] = []
        legacy.apply_branch_rules(
            context.intent["category"],
            int(context.chain["chainId"]),
            context.chain.get("caip2"),
            context.tx,
            context.decoded,
            context.value_wei,
            context.from_addr,
            context.to_addr,
            impacts,
            factors,
            allow_fixture_risk=context.allow_fixture_risk,
        )
        _tag_missing_source_type(factors, "deterministic_decode")
        return RuleResult(factors, impacts)

    def contract_rules(context: RuleContext) -> RuleResult:
        factors: list[dict[str, Any]] = []
        legacy.apply_contract_reputation_rules(
            context.contract_reputation,
            factors,
            allow_fixture_risk=context.allow_fixture_risk,
            address_profile=context.address_profile,
        )
        _tag_missing_source_type(factors, "live_provider")
        return RuleResult(factors)

    def threat_rules(context: RuleContext) -> RuleResult:
        factors: list[dict[str, Any]] = []
        legacy.apply_threat_intel_rules(context.threat_intel, factors, allow_fixture_risk=context.allow_fixture_risk)
        _tag_missing_source_type(factors, "live_provider")
        return RuleResult(factors)

    def simulation_rules(context: RuleContext) -> RuleResult:
        factors: list[dict[str, Any]] = []
        legacy.apply_simulation_rules(context.simulation, factors, category=context.intent.get("category"))
        _tag_missing_source_type(factors, "live_provider")
        return RuleResult(factors)

    def erc20_rules(context: RuleContext) -> RuleResult:
        factors: list[dict[str, Any]] = []
        apply_erc20_token_profile_rules(context.erc20_profile, factors)
        _tag_missing_source_type(factors, "derived")
        return RuleResult(factors)

    return RuleEngine(
        [
            RiskRule("legacy_branch_rules", "intent", modes, branch_rules),
            RiskRule("legacy_contract_reputation_rules", "provider", modes, contract_rules),
            RiskRule("legacy_threat_intel_rules", "provider", modes, threat_rules),
            RiskRule("legacy_simulation_rules", "provider", modes, simulation_rules),
            RiskRule("legacy_erc20_token_rules", "erc20", modes, erc20_rules),
        ]
    )


def _tag_missing_source_type(factors: list[dict[str, Any]], source_type: str) -> None:
    for factor in factors:
        factor.setdefault("sourceType", source_type)
        evidence = factor.get("evidence")
        if isinstance(evidence, dict) and "source" in evidence and "fixture" in str(evidence["source"]):
            factor["sourceType"] = "fixture"
