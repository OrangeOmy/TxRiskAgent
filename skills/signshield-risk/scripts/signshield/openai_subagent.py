from __future__ import annotations

import json
import os
from typing import Any

from .subagent_harness import parse_subagent_response


DEFAULT_MODEL = "gpt-5.5"
DEFAULT_REASONING_EFFORT = "medium"
DEFAULT_TIMEOUT = 30.0


SUBAGENT_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": ["ok", "skipped", "error"]},
        "assessments": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "conclusion": {"type": "string"},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                    "evidenceRefs": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
                    "recommendedRiskFactors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "id": {"type": "string"},
                                "domain": {"type": "string"},
                                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                                "score": {"type": "integer", "minimum": 0, "maximum": 30},
                                "title": {"type": "string"},
                                "description": {"type": "string"},
                                "evidence": {"type": "object", "additionalProperties": True},
                            },
                            "required": ["id", "domain", "severity", "score", "title", "description", "evidence"],
                        },
                    },
                },
                "required": ["id", "conclusion", "severity", "confidence", "evidenceRefs", "recommendedRiskFactors"],
            },
        },
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["status", "assessments", "limitations"],
}


SYSTEM_PROMPT = """You are a security review subagent for an EVM pre-signature risk analyzer.
You only perform advisory semantic review over the structured context.
Do not decide the final wallet verdict.
Do not invent source verification, labels, simulation outcomes, ownership facts, or provider results.
Only cite facts that appear in the context. High or critical assessments must include evidenceRefs.
Prefer concise conclusions. If evidence is insufficient, return a limitation instead of guessing."""


USER_PROMPT = """Review the provided SignShield subagent context.
Focus on:
1. source_semantic_privilege_review
2. complex_honeypot_soft_rug_review
3. protocol_domain_mismatch_review
4. simulation_trace_attack_path_review
5. unknown_or_multicall_intent_review

Only perform tasks listed in context.tasks. Use evidenceRefs as dot paths into the supplied context, such as tokenProfile.tokenSecurity.taxMutable, contractReputation.etherscan.proxy, simulation.facts.0, deterministicRiskFactors.0, providerHealth.0, or verdictPreSubagent.evidenceGate.requiresLiveEvidence.
Recommended risk factors are advisory. Do not recommend lowering risk or removing deterministic factors.

Return only the structured JSON object requested by the response schema."""


class OpenAISubagentClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        timeout: float | None = None,
        client: Any | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        self.base_url = base_url if base_url is not None else os.getenv("OPENAI_BASE_URL")
        self.model = model or os.getenv("SIGNSSHIELD_OPENAI_MODEL") or DEFAULT_MODEL
        self.reasoning_effort = reasoning_effort or os.getenv("SIGNSSHIELD_OPENAI_REASONING_EFFORT") or DEFAULT_REASONING_EFFORT
        self.timeout = timeout if timeout is not None else _float_env("SIGNSSHIELD_OPENAI_TIMEOUT", DEFAULT_TIMEOUT)
        self.client = client

    def assess(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self.api_key and self.client is None:
            return _error("OPENAI_API_KEY is not configured.")
        try:
            raw = self._request(context)
        except Exception as exc:
            return _error(f"OpenAI subagent request failed: {exc}")
        parsed = _parse_model_result(raw)
        validated = parse_subagent_response(parsed)
        return enforce_evidence_refs(validated, context)

    def _request(self, context: dict[str, Any]) -> Any:
        client = self.client or self._build_client()
        response = client.responses.create(
            model=self.model,
            reasoning={"effort": self.reasoning_effort},
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": USER_PROMPT},
                        {"type": "input_text", "text": json.dumps(context, ensure_ascii=False, sort_keys=True)},
                    ],
                },
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "signshield_subagent_result",
                    "strict": True,
                    "schema": SUBAGENT_RESPONSE_SCHEMA,
                }
            },
        )
        return response

    def _build_client(self) -> Any:
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": self.api_key, "timeout": self.timeout}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)


def run_openai_subagent(context: dict[str, Any], *, client: OpenAISubagentClient | None = None) -> dict[str, Any]:
    return (client or OpenAISubagentClient()).assess(context)


def enforce_evidence_refs(result: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    if result.get("status") != "ok":
        return result
    limitations = list(result.get("limitations", []))
    assessments = []
    for assessment in result.get("assessments", []):
        refs = [ref for ref in assessment.get("evidenceRefs", []) if isinstance(ref, str) and ref.strip()]
        refs = refs[:20]
        invalid_refs = [ref for ref in refs if context is not None and not evidence_ref_exists(context, ref)]
        if invalid_refs:
            limitations.append(f"Dropped {assessment.get('id')}: evidenceRefs not found: {', '.join(invalid_refs[:5])}.")
            continue
        severity = assessment.get("severity")
        if severity in {"HIGH", "CRITICAL"} and not refs:
            limitations.append(f"Dropped {assessment.get('id')}: HIGH/CRITICAL assessment requires evidenceRefs.")
            continue
        assessment = {**assessment, "evidenceRefs": refs}
        assessments.append(assessment)
    return {"status": "ok", "assessments": assessments, "limitations": limitations}


def evidence_ref_exists(context: dict[str, Any], ref: str) -> bool:
    current: Any = context
    for part in ref.split("."):
        if isinstance(current, dict):
            if part not in current:
                return False
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return False
        else:
            return False
    return True


def _parse_model_result(value: Any) -> Any:
    output_text = getattr(value, "output_text", None)
    if output_text:
        return output_text
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value
    return _error("OpenAI response did not include output_text.")


def _error(message: str) -> dict[str, Any]:
    return {"status": "error", "assessments": [], "limitations": [message]}


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default
