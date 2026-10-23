from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soclab.adapters.firewall import (
    AdapterResult,
    DryRunFirewallAdapter,
    FirewallAdapter,
    create_firewall_adapter,
)
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.exceptions import ConfigurationError
from soclab.services.audit import AuditLogger
from soclab.services.dedup import AlertDeduplicator
from soclab.services.policy import ResponseAction, ResponsePolicy
from soclab.services.response import ResponseService


class RecordingAdapter(FirewallAdapter):
    """Adapter that records the IPs the engine asked it to block."""

    name = "recording"
    dry_run = True

    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block_ip(self, ip: str) -> AdapterResult:
        self.blocked.append(ip)
        return AdapterResult(
            adapter=self.name,
            executed=False,
            dry_run=True,
            command=f"recorded {ip}",
            message=f"would block {ip}",
        )


def _service(tmp_path: Path, adapter: FirewallAdapter) -> ResponseService:
    return ResponseService(
        policy=ResponsePolicy(),
        adapter=adapter,
        deduplicator=AlertDeduplicator(tmp_path / "state.db"),
        audit=AuditLogger(tmp_path / "logs" / "audit.jsonl"),
    )


def _alert(alert_id: str, severity: AlertSeverity, src_ip: str) -> SecurityAlert:
    return SecurityAlert(
        alert_id=alert_id,
        timestamp=datetime.now(UTC),
        severity=severity,
        src_ip=src_ip,
        signature="test",
    )


def test_critical_alert_uses_dry_run_and_never_executes(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    service = _service(tmp_path, adapter)

    outcome = service.handle(_alert("a1", AlertSeverity.CRITICAL, "203.0.113.99"))

    assert outcome.action is ResponseAction.BLOCK_IP
    assert outcome.executed is False
    assert outcome.dry_run is True
    assert adapter.blocked == ["203.0.113.99"]
    assert "would block" in outcome.reason


def test_protected_ip_skips_the_adapter(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    service = _service(tmp_path, adapter)

    outcome = service.handle(_alert("a2", AlertSeverity.CRITICAL, "127.0.0.1"))

    assert outcome.action is ResponseAction.NOTIFY
    assert outcome.protected is True
    assert adapter.blocked == []


def test_duplicate_alert_id_is_ignored(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    service = _service(tmp_path, adapter)
    alert = _alert("dup-1", AlertSeverity.CRITICAL, "203.0.113.50")

    first = service.handle(alert)
    second = service.handle(alert)

    assert first.duplicate is False
    assert second.duplicate is True
    assert second.action is ResponseAction.NONE
    assert adapter.blocked == ["203.0.113.50"]


def test_every_decision_is_audited_without_secrets(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    service = ResponseService(
        policy=ResponsePolicy(),
        adapter=DryRunFirewallAdapter(platform_name="Linux"),
        deduplicator=AlertDeduplicator(tmp_path / "state.db"),
        audit=AuditLogger(path),
    )

    service.handle(_alert("audit-1", AlertSeverity.HIGH, "203.0.113.10"))
    service.handle(_alert("audit-1", AlertSeverity.HIGH, "203.0.113.10"))

    lines = path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]

    assert [event["action"] for event in events] == ["NOTIFY", "NONE"]
    assert [event["duplicate"] for event in events] == [False, True]
    assert all("token" not in json.dumps(event).lower() for event in events)


def test_default_adapter_is_dry_run() -> None:
    assert isinstance(create_firewall_adapter(), DryRunFirewallAdapter)


def test_live_adapter_refuses_unsupported_platform() -> None:
    with pytest.raises(ConfigurationError):
        create_firewall_adapter(dry_run=False, platform_name="Darwin")


def test_deduplicator_reports_new_and_seen_ids(tmp_path: Path) -> None:
    dedup = AlertDeduplicator(tmp_path / "state.db")

    assert dedup.is_duplicate("x") is False
    assert dedup.is_duplicate("x") is True
    assert dedup.count() == 1
