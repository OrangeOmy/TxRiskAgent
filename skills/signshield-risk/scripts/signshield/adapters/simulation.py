from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .http import HttpClient
from ..utils import format_units, hex_to_int, normalize_address

PRESIGN_BALANCE_BUFFER_WEI = 10**21


class TenderlySimulationAdapter:
    """Tenderly Simulation API adapter.

    Requires account slug, project slug, and access key. Without them the
    adapter reports config_missing and the analyzer remains deterministic.
    """

    def __init__(
        self,
        account: str | None,
        project: str | None,
        access_key: str | None,
        client: HttpClient | None = None,
        base_url: str = "https://api.tenderly.co",
    ) -> None:
        self.account = account
        self.project = project
        self.access_key = access_key
        self.client = client or HttpClient()
        self.base_url = base_url.rstrip("/")

    def simulate(self, chain_id: int, tx: dict[str, Any]) -> dict[str, Any]:
        if not (self.account and self.project and self.access_key):
            return {"status": "config_missing", "provider": "tenderly", "facts": []}

        from_addr = normalize_address(tx.get("from"))
        value_wei = hex_to_int(tx.get("value"), 0)
        state_objects = _presign_state_objects(from_addr, value_wei)
        payload = {
            "network_id": str(chain_id),
            "from": tx.get("from"),
            "to": tx.get("to"),
            "input": tx.get("data") or "0x",
            "value": str(value_wei),
            "gas": _hex_to_decimal_int(tx.get("gas")),
            "gas_price": "0",
            "state_objects": state_objects,
            "save": False,
            "save_if_fails": False,
            "simulation_type": "full",
        }
        payload = {key: value for key, value in payload.items() if value is not None}
        headers = {"X-Access-Key": self.access_key}
        try:
            data = self.client.post_json(
                f"{self.base_url}/api/v1/account/{self.account}/project/{self.project}/simulate",
                payload=payload,
                headers=headers,
            )
        except Exception as exc:
            return {"status": "error", "provider": "tenderly", "error": _summarize_error(exc), "facts": []}

        simulation = _simulation_view(data)
        facts = _extract_simulation_facts(simulation, wallet=from_addr)
        return {
            "status": "ok",
            "provider": "tenderly",
            "facts": facts,
            "rawSummary": _summarize_simulation(simulation, presign_overrides=bool(state_objects)),
        }


def _hex_to_decimal_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith(("0x", "0X")) else int(value)
        except ValueError:
            return None
    return None


def _presign_state_objects(from_addr: str | None, value_wei: int) -> dict[str, dict[str, str]] | None:
    if not from_addr:
        return None
    balance = max(value_wei + PRESIGN_BALANCE_BUFFER_WEI, PRESIGN_BALANCE_BUFFER_WEI)
    return {from_addr: {"balance": str(balance)}}


def _simulation_view(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    simulation = data.get("simulation") if isinstance(data.get("simulation"), dict) else {}
    view = dict(simulation) if simulation else dict(data)
    transaction = data.get("transaction")
    if isinstance(transaction, dict):
        view["transaction"] = transaction
    if data.get("error") is not None:
        view["error"] = data.get("error")
    return view


def _extract_simulation_facts(simulation: dict[str, Any], *, wallet: str | None = None) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    if not isinstance(simulation, dict):
        return facts
    tx_info = _transaction_info(simulation)
    status = simulation.get("status")
    error = simulation.get("error_message") or simulation.get("error") or tx_info.get("error_message") or tx_info.get("error")
    if status is False or error:
        facts.append({"type": "revert_or_error", "message": _string_or_none(error)})

    for change in _list_at(tx_info, "asset_changes") + _list_at(simulation, "asset_changes"):
        normalized = _normalize_asset_change(change, wallet)
        if normalized:
            facts.append(normalized)
    for change in _list_at(tx_info, "balance_changes") + _list_at(simulation, "balance_changes"):
        normalized = _normalize_balance_change(change, wallet)
        if normalized:
            facts.append(normalized)
    for key in ("balance_diff", "balance_diffs"):
        for change in _as_list(simulation.get(key)):
            normalized = _normalize_balance_change(change, wallet)
            if normalized:
                facts.append(normalized)

    facts.extend(_extract_approval_facts(tx_info, wallet))
    call_trace = tx_info.get("call_trace") or _nested_get(simulation, ("transaction", "call_trace"))
    if call_trace:
        facts.append({"type": "call_trace_present", "value": True, "callCount": _count_calls(call_trace)})
    return facts


def _summarize_simulation(simulation: dict[str, Any], *, presign_overrides: bool = False) -> dict[str, Any]:
    if not isinstance(simulation, dict):
        return {}
    tx_info = _transaction_info(simulation)
    return {
        "id": simulation.get("id"),
        "status": simulation.get("status"),
        "error": simulation.get("error") or simulation.get("error_message") or tx_info.get("error") or tx_info.get("error_message"),
        "gasUsed": simulation.get("gas_used") or tx_info.get("gas_used"),
        "blockNumber": simulation.get("block_number") or tx_info.get("block_number"),
        "assetChangeCount": len(_list_at(tx_info, "asset_changes") + _list_at(simulation, "asset_changes")),
        "balanceChangeCount": len(_list_at(tx_info, "balance_changes") + _list_at(simulation, "balance_changes")),
        "presignOverrides": {"gasPrice": "0", "fromBalance": "synthetic"} if presign_overrides else None,
    }


def _transaction_info(simulation: dict[str, Any]) -> dict[str, Any]:
    transaction = simulation.get("transaction")
    if isinstance(transaction, dict):
        info = transaction.get("transaction_info")
        if isinstance(info, dict):
            return info
        return transaction
    info = simulation.get("transaction_info")
    return info if isinstance(info, dict) else {}


def _normalize_asset_change(change: Any, wallet: str | None) -> dict[str, Any] | None:
    if not isinstance(change, dict):
        return None
    from_addr = _first_address(change, ("from", "from_address", "sender", "src"))
    to_addr = _first_address(change, ("to", "to_address", "recipient", "dst"))
    token_info = change.get("token_info") if isinstance(change.get("token_info"), dict) else {}
    token_address = _first_address(change, ("token_address", "contract_address", "asset_address")) or _first_address(token_info, ("address", "contract_address"))
    decimals = _int_or_none(change.get("decimals")) if change.get("decimals") is not None else _int_or_none(token_info.get("decimals"))
    amount_raw = _amount_raw(change)
    normalized: dict[str, Any] = {
        "type": "asset_change",
        "assetType": change.get("asset_type") or change.get("type") or token_info.get("type"),
        "from": from_addr,
        "to": to_addr,
        "tokenAddress": token_address,
        "symbol": change.get("symbol") or token_info.get("symbol"),
        "name": change.get("name") or token_info.get("name"),
        "amountRaw": str(amount_raw) if amount_raw is not None else _string_or_none(change.get("raw_amount") or change.get("amount")),
        "amountFormatted": _formatted_amount(amount_raw, decimals, change),
        "walletDirection": _wallet_transfer_direction(wallet, from_addr, to_addr),
    }
    if change.get("dollar_value") is not None:
        normalized["dollarValue"] = change.get("dollar_value")
    return {key: value for key, value in normalized.items() if value is not None}


def _normalize_balance_change(change: Any, wallet: str | None) -> dict[str, Any] | None:
    if not isinstance(change, dict):
        return None
    address = _first_address(change, ("address", "account", "wallet"))
    token_info = change.get("token_info") if isinstance(change.get("token_info"), dict) else {}
    token_address = _first_address(change, ("token_address", "contract_address", "asset_address")) or _first_address(token_info, ("address", "contract_address"))
    decimals = _int_or_none(change.get("decimals")) if change.get("decimals") is not None else _int_or_none(token_info.get("decimals"))
    delta_raw = _amount_raw(change, keys=("delta", "raw_amount", "amount", "diff", "balance_diff"))
    delta_display = _decimal_amount(change, keys=("delta", "amount", "diff", "balance_diff"))
    direction = _balance_direction(delta_raw, delta_display) if wallet and address == wallet else None
    normalized: dict[str, Any] = {
        "type": "balance_change",
        "address": address,
        "tokenAddress": token_address,
        "symbol": change.get("symbol") or token_info.get("symbol"),
        "amountRaw": str(delta_raw) if delta_raw is not None else _string_or_none(change.get("amount") or change.get("delta")),
        "amountFormatted": _formatted_amount(delta_raw, decimals, change),
        "walletDirection": direction,
    }
    return {key: value for key, value in normalized.items() if value is not None}


def _extract_approval_facts(tx_info: dict[str, Any], wallet: str | None) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for log in _list_at(tx_info, "logs"):
        if not isinstance(log, dict):
            continue
        name = str(log.get("name") or log.get("event") or "").lower()
        if name != "approval":
            continue
        inputs = log.get("inputs") if isinstance(log.get("inputs"), list) else []
        fields = _event_input_map(inputs)
        owner = normalize_address(fields.get("owner"))
        spender = normalize_address(fields.get("spender"))
        raw_value = fields.get("value")
        amount = hex_to_int(raw_value, 0) if raw_value is not None else None
        if not (owner and spender and raw_value is not None):
            continue
        facts.append(
            {
                "type": "approval_change",
                "owner": owner,
                "spender": spender,
                "tokenAddress": _first_address(log, ("address", "contract_address")),
                "amountRaw": str(amount) if amount is not None else None,
                "walletOwner": owner == wallet if wallet and owner else None,
            }
        )
    return [{key: value for key, value in fact.items() if value is not None} for fact in facts]


def _event_input_map(inputs: list[Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for item in inputs:
        if isinstance(item, dict) and item.get("name"):
            fields[str(item["name"])] = item.get("value")
    return fields


def _wallet_transfer_direction(wallet: str | None, from_addr: str | None, to_addr: str | None) -> str | None:
    if not wallet:
        return None
    if from_addr == wallet and to_addr != wallet:
        return "out"
    if to_addr == wallet and from_addr != wallet:
        return "in"
    if from_addr == wallet and to_addr == wallet:
        return "self"
    return None


def _amount_raw(change: dict[str, Any], keys: tuple[str, ...] = ("raw_amount", "amount_raw", "amount", "value")) -> int | None:
    for key in keys:
        value = change.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            value = value.get("raw") or value.get("value")
        if isinstance(value, str) and "." in value:
            continue
        parsed = hex_to_int(value, None)  # type: ignore[arg-type]
        if parsed is not None:
            return parsed
    return None


def _decimal_amount(change: dict[str, Any], keys: tuple[str, ...]) -> Decimal | None:
    for key in keys:
        value = change.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            value = value.get("formatted") or value.get("display") or value.get("amount") or value.get("value")
        try:
            return Decimal(str(value).strip())
        except (InvalidOperation, ValueError):
            continue
    return None


def _balance_direction(delta_raw: int | None, delta_display: Decimal | None) -> str | None:
    if delta_raw is not None:
        return "out" if delta_raw < 0 else "in" if delta_raw > 0 else "none"
    if delta_display is not None:
        return "out" if delta_display < 0 else "in" if delta_display > 0 else "none"
    return None


def _formatted_amount(amount_raw: int | None, decimals: int | None, change: dict[str, Any]) -> str | None:
    for key in ("amount_formatted", "amount", "display_amount"):
        value = change.get(key)
        if isinstance(value, str) and "." in value:
            return value
    if amount_raw is None or decimals is None:
        return None
    return format_units(abs(amount_raw), decimals)


def _first_address(source: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        address = normalize_address(source.get(key))
        if address:
            return address
    return None


def _list_at(source: dict[str, Any], key: str) -> list[Any]:
    return _as_list(source.get(key))


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def _nested_get(source: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = source
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _int_or_none(value: Any) -> int | None:
    parsed = hex_to_int(value, None)  # type: ignore[arg-type]
    return parsed if isinstance(parsed, int) else None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _count_calls(call_trace: Any) -> int:
    if not isinstance(call_trace, dict):
        return 1 if call_trace else 0
    children = call_trace.get("calls") or call_trace.get("children") or []
    return 1 + sum(_count_calls(child) for child in children if isinstance(child, dict))


def _summarize_error(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if response is not None:
        try:
            data = response.json()
        except Exception:
            data = None
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict) and error.get("message"):
                return f"HTTP {status_code}: {str(error['message'])[:260]}"
            if data.get("message"):
                return f"HTTP {status_code}: {str(data['message'])[:260]}"
    if status_code:
        return f"HTTP {status_code}: {str(exc)[:220]}"
    return str(exc)[:300]
