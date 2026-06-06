from __future__ import annotations

import os
import secrets
from typing import Any
from uuid import uuid4

import yaml
from fastapi import FastAPI, Header, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .runtime import DefenseRuntime
from .types import DEFAULT_REQUEST_TIMEOUT, AnalysisOptions


SCHEMA_VERSION = "signshield-risk/v0.2"
SERVICE_NAME = "tx-risk-agent"
VALID_MODES = {"offline", "live-best-effort", "production"}
API_KEY_ENV = "TX_RISK_API_KEY"


class TransactionScanRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    chain_id: str | int | None = Field(
        default=None,
        alias="chainId",
        description="EVM chain id as a number, decimal string, hex string, or CAIP-2 value such as eip155:1.",
        examples=["eip155:1"],
    )
    transaction_origin: str | None = Field(
        default=None,
        alias="transactionOrigin",
        description="Originating dapp or site URL, when available.",
        examples=["https://app.example"],
    )
    transaction: dict[str, Any] | None = Field(
        default=None,
        description="Wallet transaction object. Flat transaction fields are also accepted at the top level.",
        examples=[
            {
                "from": "0xb7c360aaa4c2b9f727ff934baa6ba300ccc0f284",
                "to": "0x000000000000000000000000000000000000dead",
                "value": "0x1",
                "data": "0x",
            }
        ],
    )


class ErrorResponse(BaseModel):
    error: str
    message: str
    requestId: str


RiskReport = dict[str, Any]


def create_app(*, runtime: DefenseRuntime | None = None, options: AnalysisOptions | None = None) -> FastAPI:
    effective_runtime = runtime or DefenseRuntime(options or options_from_env())
    mode = effective_runtime.options.mode or ("live-best-effort" if effective_runtime.options.live else "offline")

    app = FastAPI(
        title="TxRiskAgent HTTP Service",
        version="0.1.0",
        description="Pre-signature EVM transaction risk scanner.",
    )
    app.state.runtime = effective_runtime
    app.state.mode = mode
    app.state.api_key = os.getenv(API_KEY_ENV, "")
    app.openapi = lambda: _openapi_schema(app)  # type: ignore[method-assign]

    cors_origins = _csv_env("SIGNSSHIELD_CORS_ORIGINS")
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": SERVICE_NAME,
            "schemaVersion": SCHEMA_VERSION,
            "mode": app.state.mode,
        }

    @app.get("/openapi.yaml", include_in_schema=False)
    def openapi_yaml(request: Request) -> Response:
        schema = app.openapi()
        schema["servers"] = [{"url": str(request.base_url).rstrip("/")}]
        return Response(
            content=yaml.safe_dump(schema, sort_keys=False, allow_unicode=True),
            media_type="application/yaml",
        )

    @app.post(
        "/tx-scan",
        response_model=RiskReport,
        responses={
            400: {"model": ErrorResponse, "description": "Invalid JSON request body."},
            401: {"model": ErrorResponse, "description": "Missing or invalid API key."},
            500: {"model": ErrorResponse, "description": "Unexpected scan failure."},
        },
        summary="Scan an EVM transaction before signing",
    )
    async def tx_scan(
        request: Request,
        response: Response,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> Any:
        request_id = uuid4().hex
        response.headers["X-Request-Id"] = request_id
        if not _api_key_is_valid(app.state.api_key, x_api_key):
            return _error_response(
                status.HTTP_401_UNAUTHORIZED,
                "unauthorized",
                "Missing or invalid API key.",
                request_id,
                response,
            )

        try:
            payload = await request.json()
        except Exception:
            return _error_response(
                400,
                "invalid_json",
                "Request body must be a JSON object.",
                request_id,
                response,
            )

        if not isinstance(payload, dict):
            return _error_response(
                400,
                "invalid_json",
                "Request body must be a JSON object.",
                request_id,
                response,
            )

        try:
            return app.state.runtime.analyze(payload, input_ref=f"http:tx-scan:{request_id}")
        except Exception as exc:
            return _error_response(
                500,
                "internal_error",
                f"Transaction scan failed: {exc.__class__.__name__}.",
                request_id,
                response,
            )

    return app


def options_from_env() -> AnalysisOptions:
    mode = os.getenv("SIGNSSHIELD_HTTP_MODE", "production").strip() or "production"
    if mode not in VALID_MODES:
        raise ValueError(f"SIGNSSHIELD_HTTP_MODE must be one of: {', '.join(sorted(VALID_MODES))}")

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
        subagent_mode=os.getenv("SIGNSSHIELD_SUBAGENT_MODE", "off"),
        subagent_command=os.getenv("SIGNSSHIELD_SUBAGENT_COMMAND"),
        allow_fixture_risk=False,
    )


def _error_response(status_code: int, error: str, message: str, request_id: str, response: Response) -> JSONResponse:
    response.headers["X-Request-Id"] = request_id
    return JSONResponse(
        status_code=status_code,
        headers={"X-Request-Id": request_id},
        content={"error": error, "message": message, "requestId": request_id},
    )


def _api_key_is_valid(expected: str, provided: str | None) -> bool:
    if not expected:
        return True
    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


def _openapi_schema(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas["TransactionScanRequest"] = TransactionScanRequest.model_json_schema(
        by_alias=True,
        ref_template="#/components/schemas/{model}",
    )
    schemas["ErrorResponse"] = ErrorResponse.model_json_schema(ref_template="#/components/schemas/{model}")
    components.setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }

    tx_scan = schema["paths"]["/tx-scan"]["post"]
    tx_scan["security"] = [{"ApiKeyAuth": []}]
    tx_scan["requestBody"] = {
        "required": True,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/TransactionScanRequest"}
            }
        },
    }
    tx_scan.pop("parameters", None)

    app.openapi_schema = schema
    return schema


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return float(value)


def _csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


app = create_app()
