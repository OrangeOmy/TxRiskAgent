from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace

from signshield.openai_subagent import OpenAISubagentClient, enforce_evidence_refs, evidence_ref_exists
from signshield.subagent_harness import parse_subagent_response


class FakeResponses:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(output_text=json.dumps(self.payload))


class FakeOpenAI:
    def __init__(self, payload: dict) -> None:
        self.responses = FakeResponses(payload)


def test_openai_subagent_accepts_structured_result_from_fake_client() -> None:
    payload = {
        "status": "ok",
        "assessments": [
            {
                "id": "source_semantic_privilege_review",
                "conclusion": "Owner-controlled tax settings can affect exits.",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "evidenceRefs": ["tokenProfile.tokenSecurity.taxMutable"],
                "recommendedRiskFactors": [],
            }
        ],
        "limitations": [],
    }
    fake = FakeOpenAI(payload)
    result = OpenAISubagentClient(api_key="test-key", client=fake).assess(
        {"schemaVersion": "signshield-subagent-context/v0.1", "tokenProfile": {"tokenSecurity": {"taxMutable": True}}}
    )
    assert parse_subagent_response(result)["status"] == "ok"
    assert result["assessments"][0]["id"] == "source_semantic_privilege_review"
    assert fake.responses.calls[0]["model"] == "gpt-5.5"
    assert fake.responses.calls[0]["reasoning"] == {"effort": "medium"}


def test_openai_subagent_missing_api_key_returns_structured_error(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = OpenAISubagentClient(api_key=None, client=None).assess({})
    assert result == {"status": "error", "assessments": [], "limitations": ["OPENAI_API_KEY is not configured."]}


def test_high_severity_assessment_without_evidence_refs_is_dropped() -> None:
    result = enforce_evidence_refs(
        {
            "status": "ok",
            "assessments": [
                {
                    "id": "bad_high",
                    "conclusion": "Too strong without evidence.",
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "evidenceRefs": [],
                    "recommendedRiskFactors": [],
                },
                {
                    "id": "low_note",
                    "conclusion": "Low confidence note.",
                    "severity": "LOW",
                    "confidence": "LOW",
                    "evidenceRefs": [],
                    "recommendedRiskFactors": [],
                },
            ],
            "limitations": [],
        }
    )
    assert [item["id"] for item in result["assessments"]] == ["low_note"]
    assert "requires evidenceRefs" in result["limitations"][0]


def test_evidence_refs_must_resolve_when_context_is_supplied() -> None:
    result = enforce_evidence_refs(
        {
            "status": "ok",
            "assessments": [
                {
                    "id": "bad_ref",
                    "conclusion": "Reference is invented.",
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "evidenceRefs": ["tokenProfile.tokenSecurity.missing"],
                    "recommendedRiskFactors": [],
                }
            ],
            "limitations": [],
        },
        {"tokenProfile": {"tokenSecurity": {"taxMutable": True}}},
    )
    assert result["assessments"] == []
    assert "evidenceRefs not found" in result["limitations"][0]


def test_evidence_ref_exists_supports_dicts_and_lists() -> None:
    context = {"simulation": {"facts": [{"type": "asset_changes"}]}}
    assert evidence_ref_exists(context, "simulation.facts.0.type") is True
    assert evidence_ref_exists(context, "simulation.facts.1.type") is False


def test_openai_subagent_command_wrapper_reads_stdin_and_writes_json_without_key() -> None:
    env = os.environ.copy()
    env.pop("OPENAI_API_KEY", None)
    completed = subprocess.run(
        [sys.executable, "skills/signshield-risk/scripts/openai_subagent.py"],
        input=json.dumps({"schemaVersion": "signshield-subagent-context/v0.1"}),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["status"] == "error"
    assert result["assessments"] == []
