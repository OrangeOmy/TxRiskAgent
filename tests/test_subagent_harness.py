from __future__ import annotations

import json
import sys

from signshield import analyze_transaction
from signshield.subagent_context_builder import build_subagent_context
from signshield.subagent_harness import parse_subagent_response, run_subagent_harness
from signshield.types import AnalysisOptions


class FakeSubagentClient:
    def assess(self, context: dict) -> dict:
        assert context["schemaVersion"] == "signshield-subagent-context/v0.1"
        return {
            "status": "ok",
            "assessments": [
                {
                    "id": "source_semantic_privilege_review",
                    "conclusion": "Owner can indirectly change sell controls.",
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "evidenceRefs": ["evidence.erc20TokenRisk.tokenSecurity.taxMutable"],
                    "recommendedRiskFactors": [
                        {
                            "id": "subagent_owner_sell_control",
                            "domain": "uncertainty",
                            "severity": "HIGH",
                            "score": 20,
                            "title": "Subagent 识别 owner 可间接影响卖出",
                            "description": "Source review suggests owner-controlled sell path.",
                            "evidence": {"source": "fake_subagent"},
                        }
                    ],
                }
            ],
            "limitations": [],
        }


def test_subagent_context_builder_shape() -> None:
    context = build_subagent_context(
        chain={"chainId": 1},
        token_address="0x1",
        origin="https://example.invalid",
        intent={"category": "ERC20_APPROVAL"},
        decoded={"selector": "0x095ea7b3", "function": "approve(address,uint256)", "parameters": {}},
        token_profile={"metadata": {}, "tokenSecurity": {}},
        bytecode_scan={"status": "ok"},
        contract_reputation={"status": "ok"},
        threat_intel={"status": "ok"},
        simulation={"status": "not_run"},
        deterministic_risk_factors=[],
    )
    assert context["tasks"] == [
        "source_semantic_privilege_review",
        "complex_honeypot_soft_rug_review",
        "protocol_domain_mismatch_review",
        "simulation_trace_attack_path_review",
        "unknown_or_multicall_intent_review",
    ]
    assert context["providerHealth"] == []
    assert context["evidenceQuality"] == {}
    assert context["verdictPreSubagent"] == {}
    assert context["outputContract"]["status"] == "ok | skipped | error"


def test_subagent_dry_run_returns_context_without_assessments() -> None:
    result = run_subagent_harness("dry-run", {"hello": "world"})
    assert result["status"] == "skipped"
    assert result["context"] == {"hello": "world"}
    assert result["assessments"] == []


def test_subagent_response_parser_handles_invalid_json() -> None:
    result = parse_subagent_response("not json")
    assert result["status"] == "error"
    assert result["assessments"] == []


def test_fake_subagent_factor_merges_into_analysis() -> None:
    payload = {
        "chainId": "eip155:1",
        "transaction": {
            "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
            "to": "0x1000000000000000000000000000000000000103",
            "data": "0x095ea7b300000000000000000000000030000000000000000000000000000000000000010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            "value": "0x0",
        },
    }
    result = analyze_transaction(payload, options=AnalysisOptions(subagent_mode="live"), subagent_client=FakeSubagentClient())
    profile = result["evidence"]["erc20TokenRisk"]
    assert profile["subagentAssessments"][0]["id"] == "source_semantic_privilege_review"
    subagent_factor = next(factor for factor in result["riskFactors"] if factor["id"] == "subagent_owner_sell_control")
    assert subagent_factor["sourceType"] == "subagent"
    assert subagent_factor["score"] == 20


def test_unknown_contract_dry_run_gets_general_subagent_context() -> None:
    payload = {
        "chainId": "eip155:1",
        "transaction": {
            "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
            "to": "0x3000000000000000000000000000000000004216",
            "data": "0x12345678",
            "value": "0x0",
        },
    }
    result = analyze_transaction(payload, options=AnalysisOptions(subagent_mode="dry-run"))
    subagent = result["evidence"]["subagent"]
    assert subagent["status"] == "skipped"
    assert subagent["context"]["tasks"] == ["unknown_or_multicall_intent_review"]
    assert subagent["context"]["token"]["address"] is None


def test_command_subagent_harness_accepts_json_stdout(tmp_path) -> None:
    script = tmp_path / "agent.py"
    script.write_text(
        "import json, sys; json.load(sys.stdin); print(json.dumps({'status':'ok','assessments':[],'limitations':[]}))",
        encoding="utf-8",
    )
    result = run_subagent_harness("live", {"x": 1}, command=f"{sys.executable} {script}")
    assert result == {"status": "ok", "assessments": [], "limitations": []}
