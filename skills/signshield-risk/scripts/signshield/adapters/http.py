from __future__ import annotations

from typing import Any

import requests

from ..types import DEFAULT_REQUEST_TIMEOUT


class HttpClient:
    def __init__(self, timeout: float = DEFAULT_REQUEST_TIMEOUT, session: requests.Session | None = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()

    def get_json(self, url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return {"status": "unexpected_response", "raw": data}
        return data

    def post_json(self, url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        response = self.session.post(url, json=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return {"status": "unexpected_response", "raw": data}
        return data
