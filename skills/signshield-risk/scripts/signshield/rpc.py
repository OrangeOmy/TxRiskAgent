from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any
from urllib.parse import urlparse

from .adapters.http import HttpClient
from .utils import normalize_address


@dataclass(frozen=True)
class RpcEndpoint:
    chain_id: int
    chain_name: str
    url: str
    protocol: str = "http"


PUBLIC_RPC_ENDPOINTS: tuple[RpcEndpoint, ...] = (
    RpcEndpoint(1, "Ethereum", "https://ethereum-rpc.publicnode.com"),
    RpcEndpoint(1, "Ethereum", "https://1rpc.io/eth"),
    RpcEndpoint(42161, "Arbitrum One", "https://arb1.arbitrum.io/rpc"),
    RpcEndpoint(10, "Optimism / OP Mainnet", "https://mainnet.optimism.io"),
    RpcEndpoint(8453, "Base", "https://mainnet.base.org"),
    RpcEndpoint(137, "Polygon PoS", "https://polygon.drpc.org"),
    RpcEndpoint(137, "Polygon PoS", "https://polygon.publicnode.com"),
    RpcEndpoint(137, "Polygon PoS", "https://1rpc.io/matic"),
    RpcEndpoint(56, "BNB Smart Chain", "https://bsc-dataseed.bnbchain.org"),
    RpcEndpoint(56, "BNB Smart Chain", "https://bsc-dataseed-public.bnbchain.org"),
    RpcEndpoint(56, "BNB Smart Chain", "https://bsc-dataseed.defibit.io"),
    RpcEndpoint(43114, "Avalanche C-Chain", "https://api.avax.network/ext/bc/C/rpc"),
    RpcEndpoint(43114, "Avalanche C-Chain WS", "wss://api.avax.network/ext/bc/C/ws", "ws"),
)


class PublicRpcResolver:
    def __init__(
        self,
        explicit_url: str | None = None,
        *,
        client: HttpClient | None = None,
        endpoints: tuple[RpcEndpoint, ...] = PUBLIC_RPC_ENDPOINTS,
    ) -> None:
        self.explicit_url = explicit_url
        self.client = client or HttpClient(timeout=4.0)
        self.endpoints = endpoints
        self._cache: dict[int, dict[str, Any]] = {}

    def resolve(self, chain_id: int) -> dict[str, Any]:
        if self.explicit_url:
            return {
                "status": "ok",
                "source": "explicit",
                "chainId": chain_id,
                "url": self.explicit_url,
                "attempts": [],
            }
        if chain_id in self._cache:
            return self._cache[chain_id]

        candidates = [endpoint for endpoint in self.endpoints if endpoint.chain_id == chain_id]
        if not candidates:
            result = {"status": "no_public_endpoint", "source": "public_fallback", "chainId": chain_id, "attempts": []}
            self._cache[chain_id] = result
            return result

        attempts = []
        for endpoint in candidates:
            attempt = self.probe(endpoint)
            attempts.append(attempt)
            if attempt.get("status") == "ok":
                result = {
                    "status": "ok",
                    "source": "public_fallback",
                    "chainId": chain_id,
                    "url": endpoint.url,
                    "attempts": attempts,
                }
                self._cache[chain_id] = result
                return result

        result = {"status": "unavailable", "source": "public_fallback", "chainId": chain_id, "attempts": attempts}
        self._cache[chain_id] = result
        return result

    def probe(self, endpoint: RpcEndpoint) -> dict[str, Any]:
        parsed = urlparse(endpoint.url)
        protocol = endpoint.protocol or parsed.scheme
        base = {"url": endpoint.url, "chainId": endpoint.chain_id, "chainName": endpoint.chain_name, "protocol": protocol}
        if protocol not in {"http", "https"} and parsed.scheme not in {"http", "https"}:
            return {**base, "status": "unsupported_protocol"}

        started = perf_counter()
        try:
            response = self.client.post_json(
                endpoint.url,
                payload={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            )
        except Exception as exc:
            return {**base, "status": "error", "error": str(exc)}

        elapsed_ms = round((perf_counter() - started) * 1000)
        if response.get("error"):
            return {**base, "status": "error", "error": response["error"], "latencyMs": elapsed_ms}
        observed = _parse_chain_id(response.get("result"))
        if observed != endpoint.chain_id:
            return {**base, "status": "chain_mismatch", "observedChainId": observed, "latencyMs": elapsed_ms}
        return {**base, "status": "ok", "observedChainId": observed, "latencyMs": elapsed_ms}


class AddressProfileResolver:
    def __init__(
        self,
        rpc_url: str | None = None,
        client: HttpClient | None = None,
        *,
        public_fallback: bool = False,
        rpc_resolver: PublicRpcResolver | None = None,
    ) -> None:
        self.rpc_url = rpc_url
        self.client = client or HttpClient(timeout=4.0)
        self.public_fallback = public_fallback
        self.rpc_resolver = rpc_resolver or (PublicRpcResolver(client=self.client) if public_fallback and not rpc_url else None)

    def inspect(self, chain_id: int, address: str | None) -> dict[str, Any]:
        normalized = normalize_address(address)
        if not normalized:
            return {"status": "no_address", "address": address}
        rpc = self._resolve_rpc(chain_id)
        rpc_url = rpc.get("url")
        if not rpc_url:
            return {"status": rpc.get("status", "config_missing"), "address": normalized, "rpc": _rpc_summary(rpc)}
        try:
            response = self.client.post_json(
                rpc_url,
                payload={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [normalized, "latest"]},
            )
        except Exception as exc:
            return {"status": "error", "address": normalized, "error": str(exc), "rpc": _rpc_summary(rpc)}
        if response.get("error"):
            return {"status": "error", "address": normalized, "error": response["error"], "rpc": _rpc_summary(rpc)}
        code = response.get("result")
        if not isinstance(code, str):
            return {"status": "unexpected_response", "address": normalized, "result": code, "rpc": _rpc_summary(rpc)}
        clean = code.lower()
        delegation = _eip7702_delegation(clean)
        if delegation:
            return {
                "status": "ok",
                "address": normalized,
                "addressType": "EIP7702_DELEGATED_EOA",
                "isContract": True,
                "isDelegated": True,
                "delegation": delegation,
                "codeSizeBytes": max(len(clean.removeprefix("0x")) // 2, 0),
                "rpc": _rpc_summary(rpc),
            }
        is_contract = clean not in {"", "0x", "0x0"}
        return {
            "status": "ok",
            "address": normalized,
            "addressType": "CONTRACT" if is_contract else "EOA",
            "isContract": is_contract,
            "codeSizeBytes": max(len(clean.removeprefix("0x")) // 2, 0) if is_contract else 0,
            "rpc": _rpc_summary(rpc),
        }

    def _resolve_rpc(self, chain_id: int) -> dict[str, Any]:
        if self.rpc_url:
            return {"status": "ok", "source": "explicit", "chainId": chain_id, "url": self.rpc_url, "attempts": []}
        if not self.public_fallback or not self.rpc_resolver:
            return {"status": "config_missing"}
        return self.rpc_resolver.resolve(chain_id)


def check_public_rpc_endpoints(*, client: HttpClient | None = None) -> list[dict[str, Any]]:
    resolver = PublicRpcResolver(client=client)
    return [resolver.probe(endpoint) for endpoint in PUBLIC_RPC_ENDPOINTS]


def _parse_chain_id(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    try:
        if value.startswith(("0x", "0X")):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def _rpc_summary(rpc: dict[str, Any]) -> dict[str, Any]:
    return {key: rpc.get(key) for key in ("status", "source", "chainId", "url", "attempts") if rpc.get(key) is not None}


def _eip7702_delegation(code: str) -> dict[str, Any] | None:
    clean = code.lower().removeprefix("0x")
    if len(clean) != 46 or not clean.startswith("ef0100"):
        return None
    delegate = normalize_address("0x" + clean[6:])
    if not delegate:
        return None
    return {
        "type": "EIP7702",
        "indicator": "0xef0100",
        "delegateAddress": delegate,
    }
