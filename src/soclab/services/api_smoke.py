"""In-process smoke checks for the Stage 3 webhook API."""

from __future__ import annotations

import secrets
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI
from httpx import Response
from pydantic import SecretStr

from soclab.api.app import TOKEN_HEADER, create_app
from soclab.config import Settings
from soclab.services.response import ResponseService

if TYPE_CHECKING:
    from starlette.testclient import TestClient


def _test_client(app: FastAPI) -> TestClient:
    """Import TestClient lazily: importing it raises a Starlette deprecation warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from starlette.testclient import TestClient
    return TestClient(app)


@dataclass(frozen=True)
class ApiSmokeCheck:
    name: str
    passed: bool
    detail: str


def ensure_webhook_token(settings: Settings) -> Settings:
    """Return settings with a token. A throwaway token is used when unconfigured."""
    if settings.webhook_token.get_secret_value():
        return settings
    return settings.model_copy(
        update={"webhook_token": SecretStr(secrets.token_urlsafe(32))}
    )


def run_api_smoke(
    *,
    settings: Settings,
    response_service: ResponseService,
    alert_payload: dict[str, Any],
) -> list[ApiSmokeCheck]:
    """Exercise /health, /ready and /api/v1/alerts without opening a socket."""
    token = settings.webhook_token.get_secret_value()
    checks: list[ApiSmokeCheck] = []

    app = create_app(settings=settings, response_service=response_service)
    with _test_client(app) as client:
        health = client.get("/health")
        checks.append(
            ApiSmokeCheck("GET /health", health.status_code == 200, str(health.status_code))
        )

        ready = client.get("/ready")
        checks.append(
            ApiSmokeCheck("GET /ready", ready.status_code == 200, str(ready.status_code))
        )

        missing = client.post("/api/v1/alerts", json=alert_payload)
        checks.append(
            ApiSmokeCheck(
                "POST /api/v1/alerts without token",
                missing.status_code == 401,
                f"HTTP {missing.status_code}",
            )
        )

        wrong = client.post(
            "/api/v1/alerts",
            json=alert_payload,
            headers={TOKEN_HEADER: "wrong-token"},
        )
        checks.append(
            ApiSmokeCheck(
                "POST /api/v1/alerts with wrong token",
                wrong.status_code == 401,
                f"HTTP {wrong.status_code}",
            )
        )

        accepted = client.post(
            "/api/v1/alerts", json=alert_payload, headers={TOKEN_HEADER: token}
        )
        body = _json_body(accepted)
        checks.append(
            ApiSmokeCheck(
                "POST /api/v1/alerts with token",
                accepted.status_code == 200 and body.get("action") == "BLOCK_IP",
                f"HTTP {accepted.status_code} action={body.get('action', '-')}",
            )
        )

        repeated = client.post(
            "/api/v1/alerts", json=alert_payload, headers={TOKEN_HEADER: token}
        )
        repeated_body = _json_body(repeated)
        checks.append(
            ApiSmokeCheck(
                "duplicate webhook delivery",
                repeated.status_code == 200 and repeated_body.get("duplicate") is True,
                f"HTTP {repeated.status_code} duplicate={repeated_body.get('duplicate', '-')}",
            )
        )

    return checks


def _json_body(response: Response) -> dict[str, Any]:
    """Return the JSON object of a response, or an empty dict."""
    content_type = response.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        return {}
    payload: dict[str, Any] = response.json()
    return payload
