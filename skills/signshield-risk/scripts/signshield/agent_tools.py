from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, Field

from .adapters import CombinedCalldataResolver, CompositeContractReputationAdapter, CompositeThreatIntelAdapter, FourByteDirectoryResolver, SourcifyOpenChainResolver, TenderlySimulationAdapter
from .adapters.http import HttpClient
from .agent_context import build_agent_primitive_context
from .decode import decode_calldata
from .rpc import AddressProfileResolver
from .token_metadata import TokenMetadataResolver
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


class DecodeEvmCalldataParams(BaseModel):
    data: str = Field(default="0x", description="EVM transaction calldata hex string.")
    live_resolution: bool = Field(default=True, description="Whether to use Sourcify/OpenChain and 4byte selector lookup.")


class DecodeEvmCalldata(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "DecodeEvmCalldata"
    description: str = "Decode EVM calldata selector and standard parameters. Optionally resolves unknown selectors with public selector registries."
    params: type[DecodeEvmCalldataParams] = DecodeEvmCalldataParams

    async def __call__(self, params: DecodeEvmCalldataParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        resolver = None
        if params.live_resolution:
            client = HttpClient(timeout=_float_env("SIGNSSHIELD_TIMEOUT", DEFAULT_REQUEST_TIMEOUT))
            resolver = CombinedCalldataResolver([SourcifyOpenChainResolver(client=client), FourByteDirectoryResolver(client=client)])
        return ToolOk(output=json.dumps(decode_calldata(params.data, resolver), ensure_ascii=False, sort_keys=True))


class InspectEvmAddressParams(BaseModel):
    chain_id: int = Field(description="EVM chain id, e.g. 1, 56, 8453.")
    address: str = Field(description="EVM address to inspect with RPC eth_getCode.")


class InspectEvmAddress(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "InspectEvmAddress"
    description: str = "Inspect an address on-chain through RPC and report EOA/contract/EIP-7702 delegation facts."
    params: type[InspectEvmAddressParams] = InspectEvmAddressParams

    async def __call__(self, params: InspectEvmAddressParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        options = _options_from_env()
        resolver = AddressProfileResolver(
            options.rpc_url,
            client=HttpClient(timeout=options.timeout),
            public_fallback=options.public_rpc_fallback,
        )
        result = resolver.inspect(params.chain_id, params.address)
        return ToolOk(output=json.dumps(result, ensure_ascii=False, sort_keys=True))


class ReadErc20MetadataParams(BaseModel):
    chain_id: int = Field(description="EVM chain id, e.g. 1, 56, 8453.")
    token_address: str = Field(description="ERC20 token contract address.")


class ReadErc20Metadata(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "ReadErc20Metadata"
    description: str = "Read ERC20 name, symbol, decimals, and totalSupply through fixtures/RPC/explorer fallback."
    params: type[ReadErc20MetadataParams] = ReadErc20MetadataParams

    async def __call__(self, params: ReadErc20MetadataParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        options = _options_from_env()
        resolver = TokenMetadataResolver(
            options.rpc_url,
            client=HttpClient(timeout=options.timeout),
            public_fallback=options.public_rpc_fallback,
        )
        result = resolver.metadata(params.chain_id, params.token_address)
        return ToolOk(output=json.dumps(result, ensure_ascii=False, sort_keys=True))


class InspectContractReputationParams(BaseModel):
    chain_id: int = Field(description="EVM chain id, e.g. 1, 56, 8453.")
    address: str = Field(description="Contract address to inspect through Etherscan/Blockscout where configured.")


class InspectContractReputation(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "InspectContractReputation"
    description: str = "Inspect contract source verification, proxy, deployment, label, and ABI/source security signals."
    params: type[InspectContractReputationParams] = InspectContractReputationParams

    async def __call__(self, params: InspectContractReputationParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        options = _options_from_env()
        adapter = CompositeContractReputationAdapter(
            options.etherscan_api_key,
            options.blockscout_base_url,
            client=HttpClient(timeout=options.timeout),
        )
        result = adapter.inspect(params.chain_id, params.address)
        return ToolOk(output=json.dumps(result, ensure_ascii=False, sort_keys=True))


class InspectThreatIntelParams(BaseModel):
    chain_id: int = Field(description="EVM chain id, e.g. 1, 56, 8453.")
    addresses: list[str] = Field(default_factory=list, description="Addresses to check with threat-intel providers.")
    origin: str | None = Field(default=None, description="Originating dapp URL/domain, if available.")


class InspectThreatIntel(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "InspectThreatIntel"
    description: str = "Inspect addresses and origin domain through GoPlus and MetaMask phishing sources."
    params: type[InspectThreatIntelParams] = InspectThreatIntelParams

    async def __call__(self, params: InspectThreatIntelParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        options = _options_from_env()
        adapter = CompositeThreatIntelAdapter(
            options.goplus_base_url,
            options.metamask_config_url,
            client=HttpClient(timeout=options.timeout),
        )
        result = adapter.inspect(params.chain_id, params.addresses, params.origin)
        return ToolOk(output=json.dumps(result, ensure_ascii=False, sort_keys=True))


class SimulateEvmTransactionParams(BaseModel):
    chain_id: int = Field(description="EVM chain id, e.g. 1, 56, 8453.")
    transaction_json: str = Field(description="Wallet transaction JSON object as a string.")


class SimulateEvmTransaction(CallableTool2):  # type: ignore[misc,valid-type]
    name: str = "SimulateEvmTransaction"
    description: str = "Run Tenderly transaction simulation where configured and return normalized wallet-relative facts."
    params: type[SimulateEvmTransactionParams] = SimulateEvmTransactionParams

    async def __call__(self, params: SimulateEvmTransactionParams) -> ToolReturnValue:
        _ensure_sdk_tooling()
        try:
            tx = json.loads(params.transaction_json)
        except json.JSONDecodeError as exc:
            return ToolError(output="", message=f"Invalid transaction_json: {exc}", brief="Invalid transaction JSON")
        if not isinstance(tx, dict):
            return ToolError(output="", message="transaction_json must decode to an object.", brief="Invalid transaction JSON")

        options = _options_from_env()
        adapter = TenderlySimulationAdapter(
            options.tenderly_account,
            options.tenderly_project,
            options.tenderly_access_key,
            client=HttpClient(timeout=options.timeout),
        )
        result = adapter.simulate(params.chain_id, tx)
        return ToolOk(output=json.dumps(result, ensure_ascii=False, sort_keys=True))


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


def _ensure_sdk_tooling() -> None:
    if ToolOk is None or ToolError is None:
        raise RuntimeError("kimi-agent-sdk is not installed.")
