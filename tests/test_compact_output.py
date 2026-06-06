from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from signshield import analyze_transaction
from signshield.compact import compact_report
from signshield.llm_summary import LLMSummaryClient, apply_llm_summary


ROOT = Path(__file__).resolve().parents[1]


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


def load_dump(name_prefix: str) -> dict:
    path = next((ROOT / "dump-tx").glob(f"{name_prefix}*.json"))
    return json.loads(path.read_text(encoding="utf-8"))


def test_compact_report_omits_full_evidence_sections() -> None:
    full = analyze_transaction(load_dump("2026-06-03T00-01"))
    compact = compact_report(full)
    encoded = json.dumps(compact, ensure_ascii=False)

    assert compact["schemaVersion"] == "signshield-risk-compact/v0.1"
    assert compact["verdict"]["riskLevel"] == "CRITICAL"
    assert compact["keyRisks"]
    assert "erc20TokenRisk" not in encoded
    assert "contractReputation" not in compact
    assert "riskFactors" not in compact
    assert all("evidence" not in risk for risk in compact["keyRisks"])


def test_low_risk_compact_report_keeps_minimal_shape() -> None:
    full = {
        "schemaVersion": "signshield-risk/v0.2",
        "inputRef": "low.json",
        "verdict": {"riskLevel": "LOW", "score": 0, "confidence": "HIGH", "recommendedAction": "CONTINUE"},
        "summary": "LOW 风险：未发现高风险信号。",
        "intent": {"category": "NATIVE_TRANSFER", "decodedFunction": None},
        "assetImpact": [],
        "riskFactors": [],
        "evidence": {"simulation": {"status": "not_run"}, "contractReputation": {"status": "not_run"}, "threatIntel": {"status": "not_run"}},
        "recommendation": "未发现高风险信号；仍建议确认收款地址和交易金额。",
    }

    compact = compact_report(full)

    assert compact["keyRisks"] == []
    assert compact["assetImpact"] == []
    assert compact["summaryMeta"]["llm"]["status"] == "not_run"


def test_compact_report_preserves_short_reasoning_trace() -> None:
    full = {
        "schemaVersion": "signshield-risk/v0.2",
        "inputRef": "agent.json",
        "verdict": {"riskLevel": "HIGH", "score": 65, "confidence": "MEDIUM", "recommendedAction": "REVIEW_OR_REJECT"},
        "summary": "HIGH 风险：需要复核。",
        "intent": {"category": "ERC20_APPROVAL", "decodedFunction": "approve(address,uint256)"},
        "assetImpact": [],
        "riskFactors": [],
        "reasoningTrace": [
            {"step": "decode", "summary": "Decoded ERC20 approval.", "evidenceRefs": ["evidence.calldata.function"]},
            {"step": "web_search", "summary": "Search found no reputable match.", "evidenceRefs": []},
        ],
        "evidence": {"simulation": {"status": "not_run"}, "contractReputation": {"status": "not_run"}, "threatIntel": {"status": "not_run"}},
        "recommendation": "建议复核后再签名。",
    }

    compact = compact_report(full)

    assert compact["reasoningTrace"][0] == full["reasoningTrace"][0]
    assert compact["reasoningTrace"][1] == {"step": "web_search", "summary": "Search found no reputable match."}


def test_llm_summary_success_adds_summary_without_changing_verdict() -> None:
    compact = compact_report(analyze_transaction(load_dump("2026-06-02T11-14")))
    original_verdict = dict(compact["verdict"])
    fake = FakeOpenAI(
        {
            "headline": "这笔交易会转出原生币。",
            "keyFindings": ["收款地址是 dead 地址。"],
            "userMessage": "建议拒绝，除非你确认这是销毁操作。",
            "nextAction": "拒绝或重新核对收款地址。",
        }
    )

    result = apply_llm_summary(compact, client=LLMSummaryClient(api_key="test", client=fake))

    assert result["verdict"] == original_verdict
    assert result["summaryMeta"]["llm"]["status"] == "ok"
    assert result["llmSummary"]["headline"] == "这笔交易会转出原生币。"
    assert fake.responses.calls[0]["text"]["format"]["name"] == "signshield_compact_summary"


def test_llm_summary_failure_falls_back_to_deterministic_compact(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    compact = compact_report(analyze_transaction(load_dump("2026-06-02T11-14")))

    result = apply_llm_summary(compact, client=LLMSummaryClient(api_key=None, client=None))

    assert "llmSummary" not in result
    assert result["summaryMeta"]["llm"]["status"] == "error"
    assert "OPENAI_API_KEY" in result["summaryMeta"]["llm"]["error"]


def test_cli_defaults_to_compact_and_can_skip_llm() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "skills/signshield-risk/scripts/analyze_evm_tx.py",
            "dump-tx/2026-06-02T11-14-54-807Z-20571aef-0d9a-489d-b3e1-3b4aaf982fbd.json",
            "--summary-llm",
            "off",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    result = json.loads(completed.stdout)

    assert result["schemaVersion"] == "signshield-risk-compact/v0.1"
    assert result["summaryMeta"]["llm"]["status"] == "skipped"
    assert "evidence" not in result


def test_cli_full_output_preserves_current_schema_without_llm(monkeypatch) -> None:
    env = os.environ.copy()
    env.pop("OPENAI_API_KEY", None)
    completed = subprocess.run(
        [
            sys.executable,
            "skills/signshield-risk/scripts/analyze_evm_tx.py",
            "dump-tx/2026-06-02T11-14-54-807Z-20571aef-0d9a-489d-b3e1-3b4aaf982fbd.json",
            "--output-format",
            "full",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    result = json.loads(completed.stdout)

    assert result["schemaVersion"] == "signshield-risk/v0.2"
    assert "evidence" in result
    assert "llmSummary" not in result
