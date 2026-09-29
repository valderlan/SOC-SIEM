import time
from collections.abc import Mapping
from typing import Any

import httpx

from soclab.config import Settings
from soclab.exceptions import WazuhAuthenticationError, WazuhRequestError
from soclab.models import Agent, RuleMatch


def _describe_transport_error(prefix: str, exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return f"{prefix}: request timed out."
    if isinstance(exc, httpx.ConnectError):
        details = str(exc).lower()
        if "certificate" in details or "ssl" in details or "tls" in details:
            return (
                f"{prefix}: TLS verification failed. "
                "Review SOCLAB_WAZUH_VERIFY_TLS or configure SOCLAB_WAZUH_CA_BUNDLE."
            )
        return (
            f"{prefix}: could not connect to Wazuh API. "
            "Check if Wazuh is running and reachable on the configured URL."
        )
    return f"{prefix}: {exc}"


class WazuhClient:
    """Small synchronous Wazuh REST client for the Stage 1 demo.

    Authentication is performed with Basic Auth only to obtain a short-lived JWT.
    Subsequent requests use the JWT as a Bearer token.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._token: str | None = None
        self._client = httpx.Client(
            base_url=str(settings.wazuh_url).rstrip("/"),
            timeout=settings.http_timeout_seconds,
            verify=settings.httpx_verify,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    def __enter__(self) -> "WazuhClient":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _authenticate(self) -> str:
        try:
            response = self._client.post(
                "/security/user/authenticate",
                params={"raw": "true"},
                auth=(
                    self._settings.wazuh_username,
                    self._settings.wazuh_password.get_secret_value(),
                ),
            )
        except httpx.HTTPError as exc:
            message = _describe_transport_error("Wazuh authentication failed", exc)
            raise WazuhAuthenticationError(message) from exc

        if response.status_code in {401, 403}:
            raise WazuhAuthenticationError(
                f"Wazuh rejected the credentials (HTTP {response.status_code})."
            )
        if response.is_error:
            raise WazuhAuthenticationError(
                f"Wazuh authentication failed: HTTP {response.status_code}: {response.text[:300]}"
            )

        token = response.text.strip().strip('"')
        if not token:
            raise WazuhAuthenticationError(
                "Wazuh authentication returned an empty token."
            )
        self._token = token
        return token

    def _headers(self) -> dict[str, str]:
        token = self._token or self._authenticate()
        return {"Authorization": f"Bearer {token}"}

    def _get_with_transport_retry(
        self,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
    ) -> httpx.Response:
        """Retry idempotent GET requests on transient transport failures only."""
        delays = (0.0, 0.25, 0.5)
        last_error: httpx.HTTPError | None = None
        for delay in delays:
            if delay:
                time.sleep(delay)
            try:
                return self._client.get(path, params=params, headers=self._headers())
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json: Mapping[str, Any] | None = None,
        retry_get: bool = True,
    ) -> dict[str, Any]:
        try:
            if method == "GET" and retry_get:
                response = self._get_with_transport_retry(path, params=params)
            else:
                response = self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    headers=self._headers(),
                )
        except httpx.HTTPError as exc:
            message = _describe_transport_error(
                f"Wazuh request failed: {method} {path}", exc
            )
            raise WazuhRequestError(message) from exc

        # A JWT can expire. Refresh it once and retry the operation.
        if response.status_code == 401:
            self._token = None
            try:
                response = self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    headers=self._headers(),
                )
            except httpx.HTTPError as exc:
                message = _describe_transport_error(
                    "Wazuh request failed after re-authentication", exc
                )
                raise WazuhRequestError(message) from exc

        if response.is_error:
            raise WazuhRequestError(
                f"Wazuh API returned HTTP {response.status_code} for {method} {path}: "
                f"{response.text[:500]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhRequestError(
                f"Wazuh API returned non-JSON data for {method} {path}."
            ) from exc

        if not isinstance(payload, dict):
            raise WazuhRequestError(
                f"Unexpected Wazuh payload type for {method} {path}."
            )
        if payload.get("error", 0) not in {0, None}:
            raise WazuhRequestError(
                f"Wazuh application error for {method} {path}: {payload.get('message', payload)}"
            )
        return payload

    def api_info(self) -> dict[str, Any]:
        """Return Wazuh API metadata from GET /."""
        return self._request_json("GET", "/")

    def agents(self) -> list[Agent]:
        """List enrolled agents, normalized to local models."""
        payload = self._request_json(
            "GET",
            "/agents",
            params={"limit": self._settings.max_agents, "sort": "+id"},
        )
        data = payload.get("data", {})
        items = data.get("affected_items", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            raise WazuhRequestError(
                "Unexpected /agents response: affected_items is not a list."
            )
        return [Agent.model_validate(item) for item in items]

    def logtest(
        self,
        event: str,
        *,
        log_format: str = "syslog",
        location: str = "soclab->/var/log/auth.log",
    ) -> RuleMatch:
        """Evaluate an event safely in Wazuh's logtest sandbox."""
        payload = self._request_json(
            "PUT",
            "/logtest",
            json={"event": event, "log_format": log_format, "location": location},
            retry_get=False,
        )
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise WazuhRequestError("Unexpected /logtest response.")

        output = data.get("output", {})
        output = output if isinstance(output, dict) else {}
        rule = output.get("rule", {})
        rule = rule if isinstance(rule, dict) else {}
        decoder_value = output.get("decoder")
        decoder: str | None
        if isinstance(decoder_value, dict):
            decoder = (
                str(decoder_value.get("name")) if decoder_value.get("name") else None
            )
        elif decoder_value is None:
            decoder = None
        else:
            decoder = str(decoder_value)

        rule_id = rule.get("id")
        level = rule.get("level")
        return RuleMatch(
            matched=bool(rule),
            rule_id=str(rule_id) if rule_id is not None else None,
            level=int(level) if level is not None else None,
            description=(
                str(rule.get("description")) if rule.get("description") else None
            ),
            decoder=decoder,
            token=str(data.get("token")) if data.get("token") else None,
            raw_output=output,
        )

    def send_event(self, event: str) -> dict[str, Any]:
        """Forward one event to analysisd via POST /events.

        No automatic retry is used here to avoid creating duplicate live events.
        """
        return self._request_json(
            "POST",
            "/events",
            params={"wait_for_complete": "true"},
            json={"events": [event]},
            retry_get=False,
        )
