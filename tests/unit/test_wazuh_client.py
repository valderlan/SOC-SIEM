from collections.abc import Callable

import httpx
import pytest

from soclab.clients.wazuh import WazuhClient
from soclab.config import Settings
from soclab.exceptions import WazuhAuthenticationError


def settings() -> Settings:
    return Settings(
        wazuh_url="https://wazuh.test:55000",
        wazuh_username="api-user",
        wazuh_password="secret",
        wazuh_verify_tls=False,
    )


def transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_authenticates_and_lists_agents() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            assert request.url.params["raw"] == "true"
            return httpx.Response(200, text="jwt-token")
        if request.url.path == "/agents":
            assert request.headers["Authorization"] == "Bearer jwt-token"
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "win11",
                                "ip": "10.0.0.21",
                                "status": "active",
                                "os": {"name": "Microsoft Windows 11 Pro"},
                            }
                        ]
                    },
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with WazuhClient(settings(), transport=transport(handler)) as client:
        agents = client.agents()

    assert len(agents) == 1
    assert agents[0].name == "win11"
    assert agents[0].os_label == "Microsoft Windows 11 Pro"


def test_refreshes_expired_token_once() -> None:
    auth_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal auth_calls
        if request.url.path == "/security/user/authenticate":
            auth_calls += 1
            return httpx.Response(200, text=f"token-{auth_calls}")
        if request.url.path == "/":
            if request.headers["Authorization"] == "Bearer token-1":
                return httpx.Response(401, json={"error": 6003, "message": "expired"})
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "data": {"api_version": "4.14.8", "hostname": "manager"},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with WazuhClient(settings(), transport=transport(handler)) as client:
        payload = client.api_info()

    assert payload["data"]["api_version"] == "4.14.8"
    assert auth_calls == 2


def test_logtest_extracts_rule() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="token")
        if request.url.path == "/logtest":
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "data": {
                        "token": "abc123",
                        "output": {
                            "rule": {
                                "id": "5710",
                                "level": 5,
                                "description": "sshd: Attempt to login using a non-existent user",
                            },
                            "decoder": {"name": "sshd"},
                        },
                    },
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with WazuhClient(settings(), transport=transport(handler)) as client:
        match = client.logtest("sample")

    assert match.matched is True
    assert match.rule_id == "5710"
    assert match.level == 5
    assert match.decoder == "sshd"


def test_send_event_posts_one_event_without_client_retry() -> None:
    seen_body: bytes | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_body
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="token")
        if request.url.path == "/events":
            seen_body = request.content
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "message": "All events were forwarded to analysisd",
                    "data": {"total_affected_items": 1, "total_failed_items": 0},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with WazuhClient(settings(), transport=transport(handler)) as client:
        result = client.send_event("hello")

    assert result["data"]["total_affected_items"] == 1
    assert seen_body is not None and b'"hello"' in seen_body


def test_authentication_rejects_invalid_credentials() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(
                401, json={"error": 6001, "message": "invalid credentials"}
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with (
        WazuhClient(settings(), transport=transport(handler)) as client,
        pytest.raises(WazuhAuthenticationError, match="rejected the credentials"),
    ):
        client.api_info()
