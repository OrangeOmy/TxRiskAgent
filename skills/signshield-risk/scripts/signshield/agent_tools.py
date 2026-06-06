from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, Field

from .agent_context import build_agent_primitive_context
from .types import DEFAULT_REQUEST_TIMEOUT, AnalysisOptions

try:
    from kimi_agent_sdk import CallableTool2, ToolError, ToolOk, ToolReturnValue
except Exception:  # pragma: no cover - exercised only when optional SDK is missing.
    CallableTool2 = object  # type: ignore[assignment,misc]
    ToolError = None  # type: ignore[assignment]
    ToolOk = None  # type: ignore[assignment]
    ToolReturnValue = Any  # type: ignore[misc,assignment]


VALID_MODES = {"offline", "live-best-effort", "production"}


class CollectEvmPrimitivesParams(BaseModel):
    payload_json: str = Field(description="The raw wallet transaction request JSON object as a string.")
    input_ref: str = Field(default="kimi-agent-loop", description="Reference id to include in the primitive context.")
    mode: str | None = Field(
        default=None,
        description="Runtime mode: offline, live-best-effort, or production. Defaults to SIGNSSHIELD_AGENT_MODE/SIGNSSHIELD_HTTP_MODE.",
    )


class CollectEvmPrimitives(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "CollectEvmPrimitives"
    description: str = (
        "Collect normalized EVM wallet-transaction primitives for pre-signature risk analysis. "
        "Returns decoded calldata, simulation facts, contract reputation, threat intelligence, "
        "ERC20 token profile, provider health, evidence quality, and deterministic candidate risk signals."
    )
    params: type[CollectEvmPrimitivesParams] = CollectEvmPrimitivesParams

    async def __call__(self, params: CollectEvmPrimitivesParams) -> ToolReturnValue:
        if ToolOk is None or ToolError is None:
            raise RuntimeError("kimi-agent-sdk is not installed.")
        try:
            payload = json.loads(params.payload_json)
        except json.JSONDecodeError as exc:
            return ToolError(output="", message=f"Invalid payload_json: {exc}", brief="Invalid transaction JSON")
        if not isinstance(payload, dict):
            return ToolError(output="", message="payload_json must decode to an object.", brief="Invalid transaction JSON")

        try:
            context = build_agent_primitive_context(
                payload,
                input_ref=params.input_ref,
                options=_options_from_env(params.mode),
            )
        except Exception as exc:
            return ToolError(output="", message=str(exc), brief="Failed to collect EVM primitives")
        return ToolOk(output=json.dumps(context, ensure_ascii=False, sort_keys=True))


def _options_from_env(mode_override: str | None = None) -> AnalysisOptions:
    mode = (mode_override or os.getenv("SIGNSSHIELD_AGENT_MODE") or os.getenv("SIGNSSHIELD_HTTP_MODE") or "production").strip()
    if mode not in VALID_MODES:
        mode = "production"
    return AnalysisOptions(
        live=mode != "offline",
        mode=mode,
        timeout=_float_env("SIGNSSHIELD_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
        tenderly_account=os.getenv("TENDERLY_ACCOUNT_SLUG"),
        tenderly_project=os.getenv("TENDERLY_PROJECT_SLUG"),
        tenderly_access_key=os.getenv("TENDERLY_ACCESS_KEY"),
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
        blockscout_base_url=os.getenv("BLOCKSCOUT_BASE_URL"),
        rpc_url=os.getenv("SIGNSSHIELD_RPC_URL"),
        public_rpc_fallback=_bool_env("SIGNSSHIELD_PUBLIC_RPC_FALLBACK", True),
        goplus_base_url=os.getenv("GOPLUS_BASE_URL", "https://api.gopluslabs.io"),
        metamask_config_url=os.getenv(
            "METAMASK_CONFIG_URL",
            "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
        ),
        subagent_mode="off",
        allow_fixture_risk=mode == "offline" or _bool_env("SIGNSSHIELD_ALLOW_FIXTURE_RISK", False),
        agent_loop="off",
    )


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError:
        return default
