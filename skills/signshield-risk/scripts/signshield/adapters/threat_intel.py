from __future__ import annotations

from urllib.parse import urlparse
from typing import Any

from ..fixtures import ADDRESS_FIXTURES, DOMAIN_FIXTURES
from .http import HttpClient


class CompositeThreatIntelAdapter:
    def __init__(
        self,
        goplus_base_url: str = "https://api.gopluslabs.io",
        metamask_config_url: str = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
        client: HttpClient | None = None,
    ) -> None:
        self.goplus_base_url = goplus_base_url.rstrip("/")
        self.metamask_config_url = metamask_config_url
        self.client = client or HttpClient()

    def inspect(self, chain_id: int, addresses: list[str], origin: str | None) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        for address in sorted(set(addr.lower() for addr in addresses if addr)):
            fixture = ADDRESS_FIXTURES.get((chain_id, address))
            if fixture:
                matches.append({"target": address, "type": "address_fixture", "severity": "critical", **fixture})
        if origin in DOMAIN_FIXTURES:
            matches.append({"target": origin, "type": "domain_fixture", **DOMAIN_FIXTURES[origin]})

        address_security = self._goplus_address_security(chain_id, addresses)
        for match in address_security.get("matches", []):
            matches.append(match)
        goplus = self._goplus_token_security(chain_id, addresses)
        for match in goplus.get("matches", []):
            matches.append(match)
        metamask = self._metamask_domain(origin)
        if metamask.get("match"):
            matches.append(metamask["match"])

        return {
            "status": "ok" if matches else "no_matches",
            "matches": matches,
            "providers": {"goplus": goplus, "goplusAddress": address_security, "metamask": metamask},
        }

    def _goplus_address_security(self, chain_id: int, addresses: list[str]) -> dict[str, Any]:
        reports: dict[str, Any] = {}
        errors: list[dict[str, Any]] = []
        matches = []
        for address in sorted(set(addr.lower() for addr in addresses if addr)):
            try:
                data = self.client.get_json(
                    f"{self.goplus_base_url}/api/v1/address_security/{address}",
                    params={"chain_id": str(chain_id)},
                )
            except Exception as exc:
                errors.append({"target": address, "error": str(exc)[:300]})
                continue
            report = data.get("result") if isinstance(data.get("result"), dict) else {}
            if not isinstance(report, dict):
                continue
            reports[address] = report
            risk_flags = _goplus_address_risk_flags(report)
            if risk_flags:
                matches.append(
                    {
                        "source": "goplus",
                        "target": address,
                        "type": "address_security",
                        "severity": "critical" if _has_critical_address_flag(risk_flags) else "high",
                        "flags": risk_flags,
                    }
                )
        status = "ok" if reports and not errors else "partial" if reports or errors else "no_addresses"
        return {
            "status": status,
            "provider": "goplus_address_security",
            "matches": matches,
            "addressReports": reports,
            "addressErrors": errors,
        }

    def _goplus_token_security(self, chain_id: int, addresses: list[str]) -> dict[str, Any]:
        tokens = sorted(set(addr.lower() for addr in addresses if addr))
        if not tokens:
            return {"status": "no_addresses", "provider": "goplus", "matches": []}
        try:
            data = self.client.get_json(
                f"{self.goplus_base_url}/api/v1/token_security/{chain_id}",
                params={"contract_addresses": ",".join(tokens)},
            )
        except Exception as exc:
            return {"status": "error", "provider": "goplus", "error": str(exc), "matches": []}
        result = data.get("result") if isinstance(data.get("result"), dict) else {}
        matches = []
        token_reports: dict[str, Any] = {}
        for address, token_report in result.items():
            if not isinstance(token_report, dict):
                continue
            token_reports[address.lower()] = token_report
            risk_flags = _goplus_risk_flags(token_report)
            if risk_flags:
                matches.append(
                    {
                        "source": "goplus",
                        "target": address.lower(),
                        "type": "token_security",
                        "severity": "high",
                        "flags": risk_flags,
                    }
                )
        return {"status": "ok", "provider": "goplus", "matches": matches, "tokenReports": token_reports, "rawStatus": data.get("code")}

    def _metamask_domain(self, origin: str | None) -> dict[str, Any]:
        host = _host(origin)
        if not host:
            return {"status": "no_origin", "provider": "metamask_eth_phishing_detect"}
        try:
            data = self.client.get_json(self.metamask_config_url)
        except Exception as exc:
            return {"status": "error", "provider": "metamask_eth_phishing_detect", "error": str(exc)}
        blocklist = _domain_entries(data, "blocklist") | _domain_entries(data, "fuzzylist")
        allowlist = _domain_entries(data, "allowlist")
        if host in allowlist:
            return {"status": "allowlisted", "provider": "metamask_eth_phishing_detect", "host": host}
        if _domain_matches(host, blocklist):
            return {
                "status": "matched",
                "provider": "metamask_eth_phishing_detect",
                "host": host,
                "match": {
                    "source": "metamask_eth_phishing_detect",
                    "target": host,
                    "type": "domain_phishing",
                    "severity": "critical",
                },
            }
        return {"status": "no_match", "provider": "metamask_eth_phishing_detect", "host": host}


def _host(origin: str | None) -> str | None:
    if not origin:
        return None
    parsed = urlparse(origin if "://" in origin else f"https://{origin}")
    return parsed.hostname.lower() if parsed.hostname else None


def _domain_entries(data: dict[str, Any], key: str) -> set[str]:
    value = data.get(key)
    if isinstance(value, list):
        return {str(item).lower() for item in value if item}
    if isinstance(value, dict):
        domains: set[str] = set()
        for nested in value.values():
            if isinstance(nested, list):
                domains.update(str(item).lower() for item in nested if item)
        return domains
    return set()


def _domain_matches(host: str, entries: set[str]) -> bool:
    labels = host.split(".")
    candidates = {".".join(labels[index:]) for index in range(len(labels))}
    return bool(candidates & entries)


def _goplus_risk_flags(report: dict[str, Any]) -> list[str]:
    high_risk_keys = [
        "is_honeypot",
        "is_blacklisted",
        "is_malicious_contract",
        "is_proxy",
        "cannot_sell_all",
        "hidden_owner",
        "selfdestruct",
        "external_call",
    ]
    flags: list[str] = []
    for key in high_risk_keys:
        value = report.get(key)
        if value in {"1", 1, True}:
            flags.append(key)
    return flags


def _goplus_address_risk_flags(report: dict[str, Any]) -> list[str]:
    high_risk_keys = [
        "blacklist_doubt",
        "cybercrime",
        "darkweb_transactions",
        "data_source",
        "fake_kyc",
        "financial_crime",
        "honeypot_related_address",
        "malicious_address",
        "mixer",
        "number_of_malicious_contracts_created",
        "phishing_activities",
        "stealing_attack",
    ]
    flags: list[str] = []
    for key in high_risk_keys:
        value = report.get(key)
        if value in {"1", 1, True}:
            flags.append(key)
        elif key == "number_of_malicious_contracts_created":
            try:
                if int(value or 0) > 0:
                    flags.append(key)
            except (TypeError, ValueError):
                pass
    return flags


def _has_critical_address_flag(flags: list[str]) -> bool:
    return bool(
        {
            "malicious_address",
            "phishing_activities",
            "stealing_attack",
            "honeypot_related_address",
            "number_of_malicious_contracts_created",
        }
        & set(flags)
    )
