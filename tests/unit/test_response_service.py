from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soclab.adapters.firewall import (
    AdapterResult,
    DryRunFirewallAdapter,
    FirewallAdapter,
    LinuxFirewallAdapter,
    create_firewall_adapter,
    find_nft_rule_handles,
)
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.exceptions import ConfigurationError
from soclab.services.audit import AuditLogger
from soclab.services.dedup import AlertDeduplicator
from soclab.services.evidence import EvidenceCollector
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


def test_high_and_critical_alerts_collect_evidence(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "logs" / "evidence"
    service = ResponseService(
        policy=ResponsePolicy(),
        adapter=DryRunFirewallAdapter(platform_name="Linux"),
        deduplicator=AlertDeduplicator(tmp_path / "state.db"),
        audit=AuditLogger(tmp_path / "logs" / "audit.jsonl"),
        evidence=EvidenceCollector(evidence_dir),
    )

    low = service.handle(_alert("ev-low", AlertSeverity.LOW, "203.0.113.10"))
    high = service.handle(_alert("ev-high", AlertSeverity.HIGH, "203.0.113.11"))
    critical = service.handle(_alert("ev-crit", AlertSeverity.CRITICAL, "203.0.113.12"))

    assert low.evidence_path is None
    assert high.evidence_path is not None and Path(high.evidence_path).is_file()
    assert critical.evidence_path is not None and Path(critical.evidence_path).is_file()
    saved = json.loads(Path(critical.evidence_path).read_text(encoding="utf-8"))
    assert saved["alert"]["alert_id"] == "ev-crit"
    assert saved["response"]["action"] == "BLOCK_IP"


def test_find_nft_rule_handles_parses_ipv4_and_ipv6() -> None:
    chain = """
table inet filter {
\tchain input { # handle 1
\t\ttype filter hook input priority filter; policy accept;
\t\tip saddr 172.28.0.200 drop # handle 7
\t\tip saddr 172.28.0.201 accept # handle 8
\t\tip6 saddr 2001:db8::1 drop # handle 9
\t}
}
"""
    assert find_nft_rule_handles(chain, "172.28.0.200") == ["7"]
    assert find_nft_rule_handles(chain, "172.28.0.201") == []
    assert find_nft_rule_handles(chain, "2001:db8::1") == ["9"]


def test_dry_run_unblock_does_not_execute(tmp_path: Path) -> None:
    service = _service(tmp_path, DryRunFirewallAdapter(platform_name="Linux"))
    result = service.unblock("203.0.113.99")

    assert result.dry_run is True
    assert result.executed is False
    assert "would unblock 203.0.113.99" in result.message


def test_linux_adapter_unblock_deletes_matching_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> object:
        calls.append(args)
        if args[:4] == ["nft", "-a", "list", "chain"]:
            return type(
                "Proc",
                (),
                {
                    "returncode": 0,
                    "stdout": "\t\tip saddr 172.28.0.200 drop # handle 12\n",
                    "stderr": "",
                },
            )()
        return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("soclab.adapters.firewall.subprocess.run", fake_run)
    result = LinuxFirewallAdapter().unblock_ip("172.28.0.200")

    assert result.executed is True
    assert ["nft", "delete", "rule", "inet", "filter", "input", "handle", "12"] in calls


def test_deduplicator_purge_older_than_and_clear(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    dedup = AlertDeduplicator(db_path)
    now = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO processed_alerts (alert_id, first_seen) VALUES (?, ?)",
            ("old-alert", (now - timedelta(hours=2)).isoformat()),
        )
        conn.execute(
            "INSERT INTO processed_alerts (alert_id, first_seen) VALUES (?, ?)",
            ("fresh-alert", (now - timedelta(seconds=30)).isoformat()),
        )

    removed = dedup.purge_older_than(60.0, now=now)
    assert removed == 1
    assert dedup.count() == 1
    assert dedup.is_duplicate("old-alert") is False
    assert dedup.is_duplicate("fresh-alert") is True
    assert dedup.clear() == 2
    assert dedup.count() == 0


def test_deduplicator_auto_expires_with_ttl(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    dedup = AlertDeduplicator(db_path, ttl_seconds=60.0)
    stale = datetime.now(UTC) - timedelta(seconds=120)

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO processed_alerts (alert_id, first_seen) VALUES (?, ?)",
            ("stale-id", stale.isoformat()),
        )

    assert dedup.is_duplicate("stale-id") is False
    assert dedup.is_duplicate("stale-id") is True
