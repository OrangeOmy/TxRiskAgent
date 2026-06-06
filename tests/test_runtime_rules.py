from __future__ import annotations

from signshield.rules import RuleContext, RuleEngine, RuleResult, RiskRule
from signshield.runtime import DefenseRuntime
from signshield.types import AnalysisOptions


def minimal_context() -> RuleContext:
    return RuleContext(
        mode="production",
        chain={"chainId": 1},
        tx={},
        origin=None,
        from_addr=None,
        to_addr=None,
        value_wei=0,
        decoded={},
        intent={"category": "UNKNOWN_CONTRACT"},
        simulation={},
        contract_reputation={},
        threat_intel={},
        erc20_profile=None,
        provider_health=[],
        evidence_quality={},
    )


def test_rule_engine_filters_modes_and_deduplicates_factors() -> None:
    def emit(_: RuleContext) -> RuleResult:
        return RuleResult(risk_factors=[{"id": "same", "score": 1}, {"id": "same", "score": 2}])

    engine = RuleEngine(
        [
            RiskRule("skip", "test", ("offline",), emit),
            RiskRule("emit", "test", ("production",), emit),
        ]
    )
    result = engine.evaluate(minimal_context())
    assert result.risk_factors == [{"id": "same", "score": 1}]


def test_rule_engine_converts_rule_errors_to_limitations() -> None:
    def fail(_: RuleContext) -> RuleResult:
        raise RuntimeError("boom")

    result = RuleEngine([RiskRule("bad_rule", "test", ("production",), fail)]).evaluate(minimal_context())
    assert result.risk_factors == []
    assert result.limitations == ["Rule bad_rule failed: boom"]


def test_defense_runtime_facade_analyzes_payload() -> None:
    result = DefenseRuntime(AnalysisOptions(mode="offline")).analyze({"chainId": 1, "transaction": {"to": "0x000000000000000000000000000000000000dead", "value": "0x1"}})
    assert result["intent"]["category"] == "NATIVE_TRANSFER"
    assert result["evidence"]["evidenceQuality"]["mode"] == "offline"
