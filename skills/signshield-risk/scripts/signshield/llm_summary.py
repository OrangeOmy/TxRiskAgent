from __future__ import annotations

import json
import os
from typing import Any

from .openai_subagent import DEFAULT_MODEL, DEFAULT_REASONING_EFFORT, DEFAULT_TIMEOUT, _float_env


LLM_SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "headline": {"type": "string"},
        "keyFindings": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        "userMessage": {"type": "string"},
        "nextAction": {"type": "string"},
    },
    "required": ["headline", "keyFindings", "userMessage", "nextAction"],
}


SYSTEM_PROMPT = """You summarize EVM pre-signature risk reports for wallet users.
Only use facts present in the supplied compact report.
Do not change or reinterpret riskLevel, score, confidence, recommendedAction, asset amounts, addresses, or provider statuses.
Do not invent labels, simulation results, source verification, ownership facts, or threat intelligence.
For low-risk reports, stay brief and do not manufacture concerns."""


USER_PROMPT = """Return concise user-facing JSON.
headline: one short sentence.
keyFindings: 0-5 short bullets based only on keyRisks, assetImpact, reasoningTrace, and evidenceStatus.
userMessage: one paragraph in the same language style as the report summary.
nextAction: a concise action aligned with verdict.recommendedAction.
Return only the structured JSON object requested by the schema."""


class LLMSummaryClient:
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

    def summarize(self, compact: dict[str, Any]) -> dict[str, Any]:
        if not self.api_key and self.client is None:
            return _error("OPENAI_API_KEY is not configured.")
        try:
            raw = self._request(_summary_context(compact))
            parsed = _parse_model_result(raw)
            return _validate_summary(parsed)
        except Exception as exc:
            return _error(f"OpenAI summary request failed: {exc}")

    def _request(self, context: dict[str, Any]) -> Any:
        client = self.client or self._build_client()
        return client.responses.create(
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
                    "name": "signshield_compact_summary",
                    "strict": True,
                    "schema": LLM_SUMMARY_SCHEMA,
                }
            },
        )

    def _build_client(self) -> Any:
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": self.api_key, "timeout": self.timeout}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)


def apply_llm_summary(compact: dict[str, Any], *, mode: str = "live", client: LLMSummaryClient | None = None) -> dict[str, Any]:
    report = dict(compact)
    meta = dict(report.get("summaryMeta") if isinstance(report.get("summaryMeta"), dict) else {})
    if mode == "off":
        meta["llm"] = {"status": "skipped"}
        report["summaryMeta"] = meta
        return report

    result = (client or LLMSummaryClient()).summarize(report)
    if result.get("status") != "ok":
        meta["llm"] = {"status": "error", "error": _first_limitation(result)}
        report["summaryMeta"] = meta
        return report
    report["llmSummary"] = result["summary"]
    meta["llm"] = {"status": "ok"}
    report["summaryMeta"] = meta
    return report


def _summary_context(compact: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": compact.get("schemaVersion"),
        "inputRef": compact.get("inputRef"),
        "verdict": compact.get("verdict"),
        "summary": compact.get("summary"),
        "intent": compact.get("intent"),
        "assetImpact": compact.get("assetImpact"),
        "keyRisks": compact.get("keyRisks"),
        "reasoningTrace": compact.get("reasoningTrace"),
        "evidenceStatus": compact.get("evidenceStatus"),
        "recommendation": compact.get("recommendation"),
    }


def _validate_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        return _error("OpenAI summary response was not a JSON object.")
    summary = {
        "headline": str(value.get("headline") or "").strip(),
        "keyFindings": [str(item).strip() for item in value.get("keyFindings", []) if str(item).strip()][:5],
        "userMessage": str(value.get("userMessage") or "").strip(),
        "nextAction": str(value.get("nextAction") or "").strip(),
    }
    missing = [key for key in ("headline", "userMessage", "nextAction") if not summary[key]]
    if missing:
        return _error(f"OpenAI summary response missing required fields: {', '.join(missing)}.")
    return {"status": "ok", "summary": summary, "limitations": []}


def _parse_model_result(value: Any) -> Any:
    output_text = getattr(value, "output_text", None)
    if output_text:
        return output_text
    if isinstance(value, (str, dict)):
        return value
    return _error("OpenAI response did not include output_text.")


def _first_limitation(result: dict[str, Any]) -> str:
    limitations = result.get("limitations")
    if isinstance(limitations, list) and limitations:
        return str(limitations[0])[:300]
    return "LLM summary failed."


def _error(message: str) -> dict[str, Any]:
    return {"status": "error", "summary": None, "limitations": [message]}
