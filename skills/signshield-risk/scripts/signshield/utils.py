from __future__ import annotations

from decimal import Decimal, getcontext
from typing import Any

from .types import ChainRef

getcontext().prec = 80

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEAD_ADDRESSES = {
    ZERO_ADDRESS,
    "0x000000000000000000000000000000000000dead",
}

UINT256_MAX = (1 << 256) - 1
UNLIMITED_THRESHOLD = UINT256_MAX - 10_000

CHAIN_NAMES = {
    1: "Ethereum",
    10: "Optimism",
    56: "BNB Smart Chain",
    137: "Polygon",
    42161: "Arbitrum",
    8453: "Base",
    43114: "Avalanche C-Chain",
}


def normalize_address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) == 42 and text.startswith("0x"):
        hex_part = text[2:]
        if all(c in "0123456789abcdefABCDEF" for c in hex_part):
            return "0x" + hex_part.lower()
    return None


def hex_to_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return default
        try:
            if text.startswith(("0x", "0X")):
                return int(text, 16)
            return int(text)
        except ValueError:
            return default
    return default


def normalize_chain(raw: Any) -> ChainRef:
    if isinstance(raw, str) and raw.startswith("eip155:"):
        try:
            chain_id = int(raw.split(":", 1)[1])
        except ValueError:
            return ChainRef(False, raw, None, None, None)
        return ChainRef(True, raw, chain_id, f"eip155:{chain_id}", CHAIN_NAMES.get(chain_id, f"EVM chain {chain_id}"))
    if isinstance(raw, int):
        return ChainRef(True, raw, raw, f"eip155:{raw}", CHAIN_NAMES.get(raw, f"EVM chain {raw}"))
    if isinstance(raw, str) and raw.isdigit():
        chain_id = int(raw)
        return ChainRef(True, raw, chain_id, f"eip155:{chain_id}", CHAIN_NAMES.get(chain_id, f"EVM chain {chain_id}"))
    return ChainRef(False, raw, None, None, None)


def format_units(amount: int, decimals: int) -> str:
    scale = Decimal(10) ** decimals
    value = Decimal(amount) / scale
    normalized = format(value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def add_factor(
    factors: list[dict[str, Any]],
    factor_id: str,
    domain: str,
    severity: str,
    score: int,
    title: str,
    description: str,
    evidence: dict[str, Any] | None = None,
    source_type: str | None = None,
) -> None:
    normalized_evidence = evidence or {}
    for existing in factors:
        if existing.get("id") == factor_id:
            return
    factor = {
        "id": factor_id,
        "domain": domain,
        "severity": severity,
        "score": score,
        "title": title,
        "description": description,
        "evidence": normalized_evidence,
    }
    if source_type:
        factor["sourceType"] = source_type
    factors.append(factor)
