from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.domain.networks import is_protected, parse_network_list
from soclab.services.policy import ResponseAction, ResponsePolicy


def _alert(
    severity: AlertSeverity, src_ip: str | None = "203.0.113.99"
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=f"test-{severity.value}-{src_ip}",
        timestamp=datetime.now(UTC),
        severity=severity,
        src_ip=src_ip,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (AlertSeverity.LOW, ResponseAction.LOG),
        (AlertSeverity.MEDIUM, ResponseAction.LOG),
        (AlertSeverity.HIGH, ResponseAction.NOTIFY),
        (AlertSeverity.CRITICAL, ResponseAction.BLOCK_IP),
    ],
)
def test_policy_maps_severity_to_action(
    severity: AlertSeverity, expected: ResponseAction
) -> None:
    decision = ResponsePolicy().evaluate(_alert(severity))

    assert decision.action is expected
    assert decision.requested_action is expected
    assert decision.protected is False


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "10.1.2.3", "192.168.1.5"])
def test_protected_addresses_are_never_blocked(address: str) -> None:
    decision = ResponsePolicy().evaluate(_alert(AlertSeverity.CRITICAL, address))

    assert decision.action is ResponseAction.NOTIFY
    assert decision.requested_action is ResponseAction.BLOCK_IP
    assert decision.protected is True


def test_block_is_downgraded_when_alert_has_no_source_ip() -> None:
    decision = ResponsePolicy().evaluate(_alert(AlertSeverity.CRITICAL, None))

    assert decision.action is ResponseAction.NOTIFY
    assert decision.target_ip is None
    assert decision.protected is False


def test_custom_protected_networks_override_defaults() -> None:
    policy = ResponsePolicy(protected_networks="203.0.113.0/24")

    protected = policy.evaluate(_alert(AlertSeverity.CRITICAL, "203.0.113.99"))
    allowed = policy.evaluate(_alert(AlertSeverity.CRITICAL, "198.51.100.7"))

    assert protected.action is ResponseAction.NOTIFY
    assert allowed.action is ResponseAction.BLOCK_IP


def test_invalid_protected_network_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_network_list("not-a-cidr")


def test_unparseable_address_fails_closed() -> None:
    assert is_protected("definitely-not-an-ip", parse_network_list("10.0.0.0/8")) is True
