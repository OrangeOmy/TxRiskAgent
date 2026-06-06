from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any


VALID_STATUS = {"ok", "skipped", "error"}
VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


class CommandSubagentClient:
    def __init__(self, command: str, timeout: float = 30.0) -> None:
        self.command = command
        self.timeout = timeout

    def assess(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            completed = subprocess.run(
                shlex.split(self.command, posix=os.name != "nt"),
                input=json.dumps(context, ensure_ascii=False),
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except Exception as exc:
            return {"status": "error", "assessments": [], "limitations": [f"subagent command failed: {exc}"]}
        if completed.returncode != 0:
            return {
                "status": "error",
                "assessments": [],
                "limitations": [f"subagent command exited {completed.returncode}: {completed.stderr.strip()}"],
            }
        return parse_subagent_response(completed.stdout)


def run_subagent_harness(mode: str, context: dict[str, Any], *, command: str | None = None, client: Any | None = None) -> dict[str, Any]:
    if mode == "off":
        return {"status": "skipped", "assessments": [], "limitations": ["Subagent mode is off."]}
    if mode == "dry-run":
        return {"status": "skipped", "assessments": [], "limitations": ["Subagent dry-run context generated; no agent called."], "context": context}
    if mode != "live":
        return {"status": "error", "assessments": [], "limitations": [f"Unknown subagent mode: {mode}"]}
    runner = client or (CommandSubagentClient(command) if command else None)
    if runner is None:
        return {"status": "error", "assessments": [], "limitations": ["Subagent live mode requires SIGNSSHIELD_SUBAGENT_COMMAND or injected client."]}
    try:
        return parse_subagent_response(runner.assess(context)) if not isinstance(runner, CommandSubagentClient) else runner.assess(context)
    except Exception as exc:
        return {"status": "error", "assessments": [], "limitations": [f"Subagent client failed: {exc}"]}


def parse_subagent_response(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            return {"status": "error", "assessments": [], "limitations": [f"Invalid subagent JSON: {exc}"]}
    if not isinstance(value, dict):
        return {"status": "error", "assessments": [], "limitations": ["Subagent output is not a JSON object."]}

    status = value.get("status")
    if status not in VALID_STATUS:
        return {"status": "error", "assessments": [], "limitations": [f"Invalid subagent status: {status}"]}
    assessments = []
    for item in value.get("assessments", []):
        if not isinstance(item, dict):
            continue
        severity = item.get("severity")
        confidence = item.get("confidence")
        if severity not in VALID_SEVERITY or confidence not in VALID_CONFIDENCE:
            continue
        assessments.append(
            {
                "id": str(item.get("id") or "subagent_assessment"),
                "conclusion": str(item.get("conclusion") or ""),
                "severity": severity,
                "confidence": confidence,
                "evidenceRefs": [str(ref) for ref in item.get("evidenceRefs", []) if ref],
                "recommendedRiskFactors": item.get("recommendedRiskFactors", []) if isinstance(item.get("recommendedRiskFactors"), list) else [],
            }
        )
    return {
        "status": status,
        "assessments": assessments,
        "limitations": [str(item) for item in value.get("limitations", []) if item],
    }


def apply_subagent_recommended_factors(result: dict[str, Any], factors: list[dict[str, Any]]) -> None:
    from .utils import add_factor

    for assessment in result.get("assessments", []):
        for factor in assessment.get("recommendedRiskFactors", []):
            if not isinstance(factor, dict):
                continue
            add_factor(
                factors,
                str(factor.get("id") or assessment["id"]),
                str(factor.get("domain") or "uncertainty"),
                str(factor.get("severity") or assessment["severity"]),
                min(max(int(factor.get("score") or 0), 0), 30),
                str(factor.get("title") or "Subagent 风险判断"),
                str(factor.get("description") or assessment["conclusion"]),
                factor.get("evidence") if isinstance(factor.get("evidence"), dict) else {"assessmentId": assessment["id"]},
                source_type="subagent",
            )
