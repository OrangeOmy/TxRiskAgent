from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from signshield import analyze_transaction
from signshield.rpc import AddressProfileResolver, PublicRpcResolver, RpcEndpoint, check_public_rpc_endpoints
from signshield.token_metadata import TokenMetadataResolver
from signshield.types import AnalysisOptions


ROOT = Path(__file__).resolve().parents[1]


class FakeRpcClient:
    def __init__(self, responses: dict[str, dict[str, Any] | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post_json(self, url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        self.calls.append((url, payload))
        response = self.responses.get(url)
        if isinstance(response, Exception):
            raise response
        return response or {"error": {"message": "not found"}}


def load_dump(name_prefix: str) -> dict:
    path = next((ROOT / "dump-tx").glob(f"{name_prefix}*.json"))
    return json.loads(path.read_text(encoding="utf-8"))


def abi_string(value: str) -> str:
    encoded = value.encode("utf-8").hex()
    length = len(value)
    padded = encoded.ljust(((len(encoded) + 63) // 64) * 64, "0")
    return "0x" + f"{32:064x}" + f"{length:064x}" + padded


def test_public_rpc_probe_accepts_matching_chain_id() -> None:
    endpoint = RpcEndpoint(1, "Ethereum", "https://rpc.example")
    client = FakeRpcClient({"https://rpc.example": {"result": "0x1"}})
    result = PublicRpcResolver(client=client, endpoints=(endpoint,)).probe(endpoint)
    assert result["status"] == "ok"
    assert result["observedChainId"] == 1


def test_public_rpc_resolver_falls_back_after_error_and_mismatch() -> None:
    endpoints = (
        RpcEndpoint(1, "Ethereum", "https://bad.example"),
        RpcEndpoint(1, "Ethereum", "https://wrong.example"),
        RpcEndpoint(1, "Ethereum", "https://ok.example"),
    )
    client = FakeRpcClient(
        {
            "https://bad.example": RuntimeError("rate limited"),
            "https://wrong.example": {"result": "0x89"},
            "https://ok.example": {"result": "0x1"},
        }
    )
    result = PublicRpcResolver(client=client, endpoints=endpoints).resolve(1)
    assert result["status"] == "ok"
    assert result["url"] == "https://ok.example"
    assert [attempt["status"] for attempt in result["attempts"]] == ["error", "chain_mismatch", "ok"]


def test_public_rpc_resolver_skips_websocket_for_http_pipeline() -> None:
    endpoints = (RpcEndpoint(43114, "Avalanche C-Chain WS", "wss://avax.example/ws", "ws"),)
    result = PublicRpcResolver(client=FakeRpcClient({}), endpoints=endpoints).resolve(43114)
    assert result["status"] == "unavailable"
    assert result["attempts"][0]["status"] == "unsupported_protocol"


def test_explicit_rpc_url_takes_precedence_without_probe() -> None:
    client = FakeRpcClient({})
    result = PublicRpcResolver(explicit_url="https://explicit.example", client=client).resolve(1)
    assert result["status"] == "ok"
    assert result["source"] == "explicit"
    assert result["url"] == "https://explicit.example"
    assert client.calls == []


def test_address_profile_uses_eth_get_code_to_classify_eoa_and_contract() -> None:
    client = FakeRpcClient({})

    def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        client.calls.append((url, payload))
        if payload["method"] == "eth_getCode":
            address = payload["params"][0]
            if address == "0x00000000000000000000000000000000000000aa":
                return {"result": "0x"}
            return {"result": "0x60806040"}
        return {"error": {"message": "unexpected"}}

    client.post_json = post_json  # type: ignore[method-assign]
    resolver = AddressProfileResolver("https://rpc.example", client=client)

    eoa = resolver.inspect(1, "0x00000000000000000000000000000000000000aa")
    contract = resolver.inspect(1, "0x00000000000000000000000000000000000000bb")

    assert eoa["addressType"] == "EOA"
    assert eoa["isContract"] is False
    assert contract["addressType"] == "CONTRACT"
    assert contract["isContract"] is True


def test_address_profile_detects_eip7702_delegated_eoa() -> None:
    client = FakeRpcClient({})

    def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        client.calls.append((url, payload))
        if payload["method"] == "eth_getCode":
            return {"result": "0xef010063c0c19a282a1b52b07dd5a65b58948a07dae32b"}
        return {"error": {"message": "unexpected"}}

    client.post_json = post_json  # type: ignore[method-assign]
    result = AddressProfileResolver("https://rpc.example", client=client).inspect(
        56,
        "0x8865c8ff2a1cf8b235143110244f340db8513876",
    )

    assert result["addressType"] == "EIP7702_DELEGATED_EOA"
    assert result["isDelegated"] is True
    assert result["delegation"]["delegateAddress"] == "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"


def test_check_public_rpc_endpoints_probes_registered_endpoints() -> None:
    client = FakeRpcClient({"https://ethereum-rpc.publicnode.com": {"result": "0x1"}})
    results = check_public_rpc_endpoints(client=client)
    assert any(result["url"] == "https://ethereum-rpc.publicnode.com" and result["status"] == "ok" for result in results)
    assert any(result["url"].startswith("wss://") and result["status"] == "unsupported_protocol" for result in results)


def test_token_metadata_uses_public_fallback_for_eth_call() -> None:
    endpoint = RpcEndpoint(1, "Ethereum", "https://rpc.example")
    client = FakeRpcClient(
        {
            "https://rpc.example": {"result": "0x1"},
        }
    )

    def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        client.calls.append((url, payload))
        method = payload["method"]
        if method == "eth_chainId":
            return {"result": "0x1"}
        selector = payload["params"][0]["data"]
        if selector == "0x06fdde03":
            return {"result": abi_string("Demo Token")}
        if selector == "0x95d89b41":
            return {"result": abi_string("DEMO")}
        if selector == "0x313ce567":
            return {"result": hex(18)}
        if selector == "0x18160ddd":
            return {"result": hex(1_000_000)}
        return {"error": {"message": "unknown selector"}}

    client.post_json = post_json  # type: ignore[method-assign]
    resolver = PublicRpcResolver(client=client, endpoints=(endpoint,))
    metadata = TokenMetadataResolver(public_fallback=True, client=client, rpc_resolver=resolver).metadata(
        1,
        "0x9999999999999999999999999999999999999999",
        {},
    )
    assert metadata["symbol"] == "DEMO"
    assert metadata["name"] == "Demo Token"
    assert metadata["sources"] == ["rpc"]
    assert metadata["rpcStatus"]["source"] == "public_fallback"
    assert metadata["rpcStatus"]["url"] == "https://rpc.example"


def test_live_analyzer_enables_public_rpc_fallback_for_erc20_metadata() -> None:
    endpoint = RpcEndpoint(1, "Ethereum", "https://rpc.example")
    client = FakeRpcClient({})

    def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        client.calls.append((url, payload))
        if payload["method"] == "eth_chainId":
            return {"result": "0x1"}
        selector = payload["params"][0]["data"]
        if selector == "0x95d89b41":
            return {"result": abi_string("LIVE")}
        if selector == "0x313ce567":
            return {"result": hex(6)}
        return {"result": "0x"}

    client.post_json = post_json  # type: ignore[method-assign]
    token_provider = TokenMetadataResolver(public_fallback=True, client=client, rpc_resolver=PublicRpcResolver(client=client, endpoints=(endpoint,)))
    result = analyze_transaction(
        load_dump("2026-06-03T00-01"),
        options=AnalysisOptions(live=True),
        token_metadata_provider=token_provider,
    )
    profile = result["evidence"]["erc20TokenRisk"]
    assert profile["metadata"]["symbol"] == "LIVE"
    assert profile["metadata"]["rpcStatus"]["source"] == "public_fallback"
