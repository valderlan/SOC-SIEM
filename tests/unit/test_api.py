from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from soclab.api.app import TOKEN_HEADER, create_app
from soclab.config import Settings
from soclab.services.response import build_response_service


def _settings(tmp_path: Path, *, token: str = "test-token") -> Settings:
    return Settings(
        webhook_token=SecretStr(token),
        audit_log_path=tmp_path / "logs" / "audit.jsonl",
        state_db_path=tmp_path / "runtime" / "state.db",
    )


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = _settings(tmp_path)
    service = build_response_service(settings)
    with TestClient(create_app(settings=settings, response_service=service)) as test_client:
        yield test_client


def _critical_payload(alert_id: str = "api-1", src_ip: str = "203.0.113.99") -> dict[str, object]:
    return {
        "alert_id": alert_id,
        "timestamp": "2026-01-01T12:00:00Z",
        "severity": "CRITICAL",
        "src_ip": src_ip,
        "signature": "SSH brute force",
    }


def test_health_reports_dry_run(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["dry_run"] is True
    assert body["adapter"] == "dry-run"


def test_ready_is_ok_when_token_and_paths_exist(client: TestClient) -> None:
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_ready_fails_without_configured_token(tmp_path: Path) -> None:
    settings = _settings(tmp_path, token="")
    service = build_response_service(settings)

    with TestClient(create_app(settings=settings, response_service=service)) as client:
        response = client.get("/ready")
        rejected = client.post("/api/v1/alerts", json=_critical_payload())

    assert response.status_code == 503
    assert "token" in response.text
    assert rejected.status_code == 503


def test_missing_token_is_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/alerts", json=_critical_payload())

    assert response.status_code == 401
    assert "test-token" not in response.text


def test_wrong_token_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/alerts",
        json=_critical_payload(),
        headers={TOKEN_HEADER: "wrong-token"},
    )

    assert response.status_code == 401
    assert "test-token" not in response.text
    assert "wrong-token" not in response.text


def test_critical_alert_is_blocked_in_dry_run(client: TestClient) -> None:
    response = client.post(
        "/api/v1/alerts",
        json=_critical_payload(),
        headers={TOKEN_HEADER: "test-token"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "BLOCK_IP"
    assert body["executed"] is False
    assert body["dry_run"] is True
    assert body["duplicate"] is False
    assert body["target_ip"] == "203.0.113.99"
    assert "test-token" not in response.text


def test_repeated_delivery_is_deduplicated(client: TestClient) -> None:
    headers = {TOKEN_HEADER: "test-token"}
    payload = _critical_payload(alert_id="api-dup")

    first = client.post("/api/v1/alerts", json=payload, headers=headers)
    second = client.post("/api/v1/alerts", json=payload, headers=headers)

    assert first.json()["duplicate"] is False
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["action"] == "NONE"


def test_protected_source_is_downgraded_to_notify(client: TestClient) -> None:
    response = client.post(
        "/api/v1/alerts",
        json=_critical_payload(alert_id="api-protected", src_ip="127.0.0.1"),
        headers={TOKEN_HEADER: "test-token"},
    )

    body = response.json()
    assert response.status_code == 200
    assert body["action"] == "NOTIFY"
    assert body["protected"] is True


def test_unmappable_payload_returns_400(client: TestClient) -> None:
    response = client.post(
        "/api/v1/alerts",
        json={"foo": "bar"},
        headers={TOKEN_HEADER: "test-token"},
    )

    assert response.status_code == 400
    assert "severity" in response.text
