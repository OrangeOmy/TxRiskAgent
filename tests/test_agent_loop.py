from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from signshield import analyze_transaction
from signshield.agent_context import build_agent_primitive_context
from signshield.agent_loop import (
    KIMI_CODE_BASE_URL,
    KIMI_CODE_MODEL_KEY,
    KIMI_CODE_PROVIDER_KEY,
    KIMI_CODE_PROVIDER_MODEL,
    AgentLoopError,
    analyze_with_agent_loop,
    attach_tool_observability,
    build_kimi_code_config_from_env,
    finalize_agent_report,
    isolated_kimi_provider_env,
    resolve_kimi_agent_model,
    validate_agent_report,
)
from signshield.types import AnalysisOptions


ROOT = Path(__file__).resolve().parents[1]


def load_dump(name_prefix: str) -> dict:
    path = next((ROOT / "dump-tx").glob(f"{name_prefix}*.json"))
    return json.loads(path.read_text(encoding="utf-8"))


class FakeAgentLoopClient:
    def __init__(self, raw: str | dict) -> None:
        self.raw = raw
        self.prompt_text = ""

    def run(self, prompt_text: str, *, options: AnalysisOptions) -> str:
        self.prompt_text = prompt_text
        return json.dumps(self.raw) if isinstance(self.raw, dict) else self.raw


class RaisingAgentLoopClient:
    def run(self, prompt_text: str, *, options: AnalysisOptions) -> str:
        raise AgentLoopError("provider unavailable")


class FakeKimiMessage:
    def __init__(self, text: str) -> None:
        self.text = text

    def extract_text(self) -> str:
        return self.text


def valid_agent_report(input_ref: str = "<memory>") -> dict:
    return {
        "schemaVersion": "signshield-risk/v0.2",
        "inputRef": input_ref,
        "verdict": {
            "riskLevel": "HIGH",
            "score": 65,
            "confidence": "MEDIUM",
            "recommendedAction": "REVIEW_OR_REJECT",
        },
        "summary": "HIGH 风险：Agent loop 识别到大额授权，需要复核。",
        "intent": {
            "category": "ERC20_APPROVAL",
            "description": "这笔交易会授予第三方地址花费 ERC20 代币的权限。",
            "decodedFunction": "approve(address,uint256)",
        },
        "assetImpact": [],
        "riskFactors": [
            {
                "id": "agent_large_allowance",
                "domain": "technical",
                "severity": "HIGH",
                "score": 35,
                "title": "授权额度较大",
                "description": "Agent 根据 primitive context 判断该授权需要复核。",
                "evidence": {"source": "deterministicRiskSignals.0"},
            }
        ],
        "reasoningTrace": [
            {
                "step": "decode",
                "summary": "Decoded calldata shows an ERC20 approval.",
                "evidenceRefs": ["evidence.calldata.function"],
            },
            {
                "step": "decision",
                "summary": "Large allowance and limited live evidence require review or rejection.",
                "evidenceRefs": ["riskFactors.0"],
            },
        ],
        "evidence": {
            "calldata": {},
            "simulation": {"status": "not_run", "facts": []},
            "contractReputation": {"status": "not_run", "facts": []},
            "threatIntel": {"status": "not_run", "matches": []},
            "erc20TokenRisk": None,
            "providerHealth": [],
            "evidenceQuality": {},
            "limitations": [],
        },
        "recommendation": "建议不要直接签名，先确认 spender 和授权额度。",
    }


def test_agent_primitive_context_exposes_existing_input_primitives() -> None:
    context = build_agent_primitive_context(load_dump("2026-06-02T09-47"), options=AnalysisOptions(mode="offline"))

    assert context["schemaVersion"] == "signshield-agent-primitives/v0.1"
    assert {item["name"] for item in context["primitiveCatalog"]} >= {
        "wallet_transaction",
        "calldata_decode",
        "simulation",
        "contract_reputation",
        "threat_intel",
        "erc20_token_profile",
    }
    assert context["intent"]["category"] == "ERC20_APPROVAL"
    assert context["evidence"]["calldata"]["function"] == "approve(address,uint256)"
    assert context["deterministicRiskSignals"]
    assert context["preliminaryVerdict"]["riskLevel"] in {"HIGH", "CRITICAL"}


def test_agent_loop_report_is_used_when_fake_client_returns_valid_json() -> None:
    client = FakeAgentLoopClient(valid_agent_report("agent-ref"))

    result = analyze_transaction(
        load_dump("2026-06-02T09-47"),
        input_ref="agent-ref",
        options=AnalysisOptions(mode="offline", agent_loop="kimi"),
        agent_loop_client=client,
    )

    assert "CollectEvmPrimitives" in client.prompt_text
    assert result["verdict"]["recommendedAction"] == "REVIEW_OR_REJECT"
    assert result["evidence"]["agentLoop"] == {"status": "ok", "backend": "kimi"}
    assert result["riskFactors"][0]["sourceType"] == "agent_loop"
    assert result["reasoningTrace"][0]["step"] == "decode"


def test_agent_loop_failure_falls_back_to_deterministic_report() -> None:
    client = FakeAgentLoopClient("not json")

    result = analyze_transaction(
        load_dump("2026-06-02T09-47"),
        options=AnalysisOptions(mode="offline", agent_loop="kimi"),
        agent_loop_client=client,
    )

    assert result["intent"]["category"] == "ERC20_APPROVAL"
    assert result["evidence"]["agentLoop"]["status"] == "error"
    assert result["evidence"]["agentLoop"]["fallback"] == "deterministic"
    assert any("Agent loop failed" in item for item in result["evidence"]["limitations"])


def test_agent_loop_provider_error_falls_back_to_deterministic_report() -> None:
    result = analyze_transaction(
        load_dump("2026-06-02T09-47"),
        options=AnalysisOptions(mode="offline", agent_loop="kimi"),
        agent_loop_client=RaisingAgentLoopClient(),
    )

    assert result["intent"]["category"] == "ERC20_APPROVAL"
    assert result["evidence"]["agentLoop"]["error"] == "provider unavailable"


def test_agent_loop_failure_records_redacted_diagnostics(monkeypatch) -> None:
    monkeypatch.setenv("KIMI_API_KEY", "secret-test-key")
    monkeypatch.setenv("KIMI_BASE_URL", "https://api.kimi.com/coding/v1")
    monkeypatch.setenv("KIMI_MODEL_NAME", "kimi-for-coding")
    monkeypatch.setenv("SIGNSSHIELD_AGENT_LOOP_MODEL", KIMI_CODE_MODEL_KEY)

    result = analyze_transaction(
        load_dump("2026-06-02T09-47"),
        options=AnalysisOptions(mode="offline", agent_loop="kimi"),
        agent_loop_client=RaisingAgentLoopClient(),
    )

    diagnostics = result["evidence"]["agentLoop"]["diagnostics"]
    assert diagnostics["resolvedModel"] == KIMI_CODE_MODEL_KEY
    assert diagnostics["env"]["KIMI_API_KEY"] == {
        "present": True,
        "empty": False,
        "length": len("secret-test-key"),
    }
    assert diagnostics["env"]["KIMI_MODEL_NAME"] == "kimi-for-coding"
    assert diagnostics["config"]["built"] is True
    assert diagnostics["config"]["resolvedModelInConfig"] is True
    assert diagnostics["config"]["providerApiKey"] == {
        "present": True,
        "empty": False,
        "length": len("secret-test-key"),
    }
    assert "secret-test-key" not in json.dumps(diagnostics)


def test_finalize_agent_report_records_failed_search_attempt() -> None:
    report = valid_agent_report("agent-ref")
    report["reasoningTrace"] = [
        {
            "step": "decision",
            "summary": "Large allowance requires review.",
            "evidenceRefs": ["riskFactors.0"],
        }
    ]

    result = finalize_agent_report(
        report,
        input_ref="agent-ref",
        backend="kimi",
        tool_events=[
            {
                "type": "tool_started",
                "step": 2,
                "toolCallId": "tool_search",
                "tool": "SearchWeb",
                "arguments": {"query": "spender scam report", "limit": 5},
            },
            {
                "type": "tool_finished",
                "step": 2,
                "toolCallId": "tool_search",
                "tool": "SearchWeb",
                "status": "error",
                "summary": "Failed to search",
            },
        ],
    )

    validate_agent_report(result)
    assert result["evidence"]["webSearch"]["status"] == "error"
    assert result["evidence"]["webSearch"]["attempts"][0] == {
        "step": 2,
        "query": "spender scam report",
        "limit": 5,
        "status": "error",
        "summary": "Failed to search",
    }
    assert [item["step"] for item in result["reasoningTrace"]] == ["web_search", "decision"]
    assert result["reasoningTrace"][0]["evidenceRefs"] == ["evidence.webSearch"]


def test_attach_tool_observability_does_not_duplicate_existing_web_search_trace() -> None:
    report = valid_agent_report("agent-ref")
    report["reasoningTrace"] = [
        {
            "step": "web_search",
            "summary": "Search found a relevant public report.",
            "evidenceRefs": [],
        },
        {
            "step": "decision",
            "summary": "Public evidence and local facts require rejection.",
            "evidenceRefs": ["riskFactors.0"],
        },
    ]

    attach_tool_observability(
        report,
        [
            {
                "type": "tool_started",
                "step": 2,
                "toolCallId": "tool_search",
                "tool": "SearchWeb",
                "arguments": {"query": "Atlantis Loans hack", "limit": 5},
            },
            {
                "type": "tool_finished",
                "step": 2,
                "toolCallId": "tool_search",
                "tool": "SearchWeb",
                "status": "ok",
                "summary": "Title: Atlantis Loans Hack",
            },
        ],
    )

    assert result_steps(report).count("web_search") == 1
    assert report["evidence"]["webSearch"]["status"] == "ok"


def test_agent_loop_can_be_configured_to_raise_on_invalid_output() -> None:
    client = FakeAgentLoopClient({"bad": "shape"})

    with pytest.raises(AgentLoopError):
        analyze_with_agent_loop(
            load_dump("2026-06-02T09-47"),
            "agent-ref",
            options=AnalysisOptions(mode="offline", agent_loop="kimi", agent_loop_fallback=False),
            client=client,
        )


def test_kimi_agent_model_defaults_to_kimi_code_model_key(monkeypatch) -> None:
    monkeypatch.delenv("SIGNSSHIELD_AGENT_LOOP_MODEL", raising=False)
    monkeypatch.delenv("KIMI_AGENT_MODEL", raising=False)

    assert resolve_kimi_agent_model(AnalysisOptions(agent_loop="kimi")) == KIMI_CODE_MODEL_KEY


def test_kimi_agent_model_uses_signshield_override(monkeypatch) -> None:
    monkeypatch.setenv("SIGNSSHIELD_AGENT_LOOP_MODEL", "custom/model-key")

    assert resolve_kimi_agent_model(AnalysisOptions(agent_loop="kimi")) == "custom/model-key"


def test_kimi_code_config_from_env_uses_kimi_code_defaults(monkeypatch) -> None:
    monkeypatch.setenv("KIMI_API_KEY", "test-key")
    monkeypatch.delenv("KIMI_BASE_URL", raising=False)
    monkeypatch.delenv("KIMI_MODEL_NAME", raising=False)

    config = build_kimi_code_config_from_env()

    assert config is not None
    assert config.default_model == KIMI_CODE_MODEL_KEY
    model = config.models[KIMI_CODE_MODEL_KEY]
    provider = config.providers[KIMI_CODE_PROVIDER_KEY]
    assert model.model == KIMI_CODE_PROVIDER_MODEL
    assert provider.base_url == KIMI_CODE_BASE_URL
    assert provider.api_key.get_secret_value() == "test-key"
    assert config.services.moonshot_search.base_url == f"{KIMI_CODE_BASE_URL}/search"
    assert config.services.moonshot_fetch.base_url == f"{KIMI_CODE_BASE_URL}/fetch"


def test_isolated_kimi_provider_env_temporarily_removes_provider_overrides(monkeypatch) -> None:
    monkeypatch.setenv("KIMI_API_KEY", "test-key")
    monkeypatch.setenv("KIMI_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("KIMI_MODEL_NAME", "bad/model-key")

    with isolated_kimi_provider_env(enabled=True):
        assert "KIMI_API_KEY" not in os.environ
        assert "KIMI_BASE_URL" not in os.environ
        assert "KIMI_MODEL_NAME" not in os.environ

    assert os.environ["KIMI_API_KEY"] == "test-key"
    assert os.environ["KIMI_BASE_URL"] == "https://example.invalid"
    assert os.environ["KIMI_MODEL_NAME"] == "bad/model-key"


def test_kimi_agent_loop_client_does_not_clear_kimi_env_during_prompt(monkeypatch) -> None:
    from signshield.agent_loop import KimiAgentLoopClient

    monkeypatch.setenv("KIMI_API_KEY", "test-key")
    monkeypatch.setenv("KIMI_BASE_URL", KIMI_CODE_BASE_URL)
    monkeypatch.setenv("KIMI_MODEL_NAME", KIMI_CODE_PROVIDER_MODEL)
    monkeypatch.setenv("SIGNSSHIELD_AGENT_LOOP_MODEL", KIMI_CODE_MODEL_KEY)

    observed_env: dict[str, str | None] = {}
    observed_call: dict[str, Any] = {}

    class FakeKimiSession:
        async def __aenter__(self) -> "FakeKimiSession":
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def prompt(self, *_args: Any, **_kwargs: Any):
            yield FakeKimiMessage(json.dumps(valid_agent_report("agent-ref")))

    async def fake_create(*args: Any, **kwargs: Any) -> FakeKimiSession:
        observed_call.update(kwargs)
        observed_env["KIMI_API_KEY"] = os.getenv("KIMI_API_KEY")
        observed_env["KIMI_BASE_URL"] = os.getenv("KIMI_BASE_URL")
        observed_env["KIMI_MODEL_NAME"] = os.getenv("KIMI_MODEL_NAME")
        return FakeKimiSession()

    monkeypatch.setattr("kimi_agent_sdk.Session.create", fake_create)

    raw = KimiAgentLoopClient().run(
        "test prompt",
        options=AnalysisOptions(agent_loop="kimi", agent_loop_model=KIMI_CODE_MODEL_KEY),
    )

    assert raw["inputRef"] == "agent-ref"
    assert observed_env == {
        "KIMI_API_KEY": "test-key",
        "KIMI_BASE_URL": KIMI_CODE_BASE_URL,
        "KIMI_MODEL_NAME": KIMI_CODE_PROVIDER_MODEL,
    }
    assert observed_call["config"] is not None
    assert observed_call["model"] == KIMI_CODE_MODEL_KEY


def result_steps(report: dict) -> list[str]:
    return [item["step"] for item in report["reasoningTrace"]]
