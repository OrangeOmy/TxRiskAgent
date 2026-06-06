from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from signshield.http_service import create_app, options_from_env
from signshield.types import AnalysisOptions


ROOT = Path(__file__).resolve().parents[1]


def client_for_offline_service() -> TestClient:
    return TestClient(create_app(options=AnalysisOptions(live=False, mode="offline")))


def load_dump(name_prefix: str) -> dict:
    path = next((ROOT / "dump-tx").glob(f"{name_prefix}*.json"))
    return json.loads(path.read_text(encoding="utf-8"))


def test_health_reports_current_mode() -> None:
    client = TestClient(create_app(options=AnalysisOptions(live=True, mode="production")))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "tx-risk-agent",
        "schemaVersion": "signshield-risk/v0.2",
        "mode": "production",
    }


def test_tx_scan_returns_risk_report_and_request_id() -> None:
    client = client_for_offline_service()

    response = client.post("/tx-scan", json=load_dump("2026-06-02T11-14"))

    body = response.json()
    request_id = response.headers["X-Request-Id"]
    assert response.status_code == 200
    assert request_id
    assert body["schemaVersion"] == "signshield-risk/v0.2"
    assert body["inputRef"] == f"http:tx-scan:{request_id}"
    assert body["verdict"]["riskLevel"] == "HIGH"
    assert body["intent"]["category"] == "NATIVE_TRANSFER"


def test_tx_scan_requires_configured_api_key(monkeypatch) -> None:
    monkeypatch.setenv("TX_RISK_API_KEY", "expected-key")
    client = client_for_offline_service()

    response = client.post("/tx-scan", json=load_dump("2026-06-02T11-14"))

    body = response.json()
    assert response.status_code == 401
    assert response.headers["X-Request-Id"] == body["requestId"]
    assert body["error"] == "unauthorized"


def test_tx_scan_accepts_configured_api_key(monkeypatch) -> None:
    monkeypatch.setenv("TX_RISK_API_KEY", "expected-key")
    client = client_for_offline_service()

    response = client.post(
        "/tx-scan",
        headers={"X-API-Key": "expected-key"},
        json=load_dump("2026-06-02T11-14"),
    )

    assert response.status_code == 200
    assert response.json()["schemaVersion"] == "signshield-risk/v0.2"


def test_tx_scan_accepts_flat_transaction_payload() -> None:
    client = client_for_offline_service()

    response = client.post(
        "/tx-scan",
        json={
            "chainId": "eip155:1",
            "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
            "to": "0x000000000000000000000000000000000000dead",
            "value": "0x1",
            "data": "0x",
        },
    )

    body = response.json()
    assert response.status_code == 200
    assert body["schemaVersion"] == "signshield-risk/v0.2"
    assert body["intent"]["category"] == "NATIVE_TRANSFER"


def test_openapi_yaml_documents_tx_scan_security_and_body(monkeypatch) -> None:
    monkeypatch.setenv("TX_RISK_API_KEY", "expected-key")
    client = client_for_offline_service()

    response = client.get("/openapi.yaml")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/yaml")
    body = response.text
    assert "/tx-scan:" in body
    assert "X-API-Key" in body
    assert "requestBody:" in body
    assert "TransactionScanRequest" in body


def test_tx_scan_rejects_non_object_json() -> None:
    client = client_for_offline_service()

    response = client.post("/tx-scan", json=["not", "an", "object"])

    body = response.json()
    assert response.status_code == 400
    assert response.headers["X-Request-Id"] == body["requestId"]
    assert body["error"] == "invalid_json"
    assert body["message"] == "Request body must be a JSON object."


def test_tx_scan_returns_unsupported_chain_as_business_result() -> None:
    client = client_for_offline_service()

    response = client.post("/tx-scan", json={"chainId": "solana:mainnet", "transaction": {}})

    body = response.json()
    assert response.status_code == 200
    assert body["schemaVersion"] == "signshield-risk/v0.2"
    assert body["verdict"]["riskLevel"] == "UNSUPPORTED"
    assert body["intent"]["category"] == "UNSUPPORTED_CHAIN"


def test_options_from_env_defaults_to_production_live(monkeypatch) -> None:
    monkeypatch.delenv("SIGNSSHIELD_HTTP_MODE", raising=False)
    monkeypatch.delenv("SIGNSSHIELD_PUBLIC_RPC_FALLBACK", raising=False)
    monkeypatch.delenv("SIGNSSHIELD_TIMEOUT", raising=False)

    options = options_from_env()

    assert options.mode == "production"
    assert options.live is True
    assert options.timeout == 30.0
    assert options.public_rpc_fallback is True
    assert options.allow_fixture_risk is False


def test_options_from_env_accepts_timeout_override(monkeypatch) -> None:
    monkeypatch.setenv("SIGNSSHIELD_TIMEOUT", "45")

    options = options_from_env()

    assert options.timeout == 45.0
