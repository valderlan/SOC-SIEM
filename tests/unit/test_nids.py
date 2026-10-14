from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from soclab.collectors.suricata import EveRecord, SuricataEveCollector
from soclab.domain.alert import AlertSeverity
from soclab.normalizers.suricata import normalize_suricata_severity
from soclab.services.nids import AlertFilters, NidsService, parse_ip_filter


def _fixture_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "suricata"
        / "eve.json"
    )


def test_validate_fixture_counts_expected_values() -> None:
    service = NidsService()

    summary = service.validate_eve_file(_fixture_path(), collect_alerts=True)

    assert summary.total_lines == 10
    assert summary.valid_json == 9
    assert summary.invalid_json == 1
    assert summary.alert_events == 5
    assert summary.ignored_events == 4
    assert summary.normalized_alerts == 5
    assert len(summary.alerts) == 5


def test_list_alerts_filters_by_severity_and_ip() -> None:
    service = NidsService()
    fixture = _fixture_path()

    alerts = service.list_alerts(
        fixture,
        filters=AlertFilters(
            severity=AlertSeverity.HIGH,
            src_ip=parse_ip_filter("198.51.100.25"),
        ),
    )

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert str(alerts[0].src_ip) == "198.51.100.25"


def test_alert_limit_returns_latest_items() -> None:
    service = NidsService()
    fixture = _fixture_path()

    alerts = service.list_alerts(fixture, filters=AlertFilters(limit=2))

    assert len(alerts) == 2
    assert alerts[-1].signature_id == 900005


def test_severity_mapping_rule() -> None:
    assert normalize_suricata_severity(1) == AlertSeverity.CRITICAL
    assert normalize_suricata_severity(2) == AlertSeverity.HIGH
    assert normalize_suricata_severity(3) == AlertSeverity.MEDIUM
    assert normalize_suricata_severity(4) == AlertSeverity.LOW
    assert normalize_suricata_severity(None) == AlertSeverity.LOW


def test_invalid_alert_schema_does_not_crash_validation(tmp_path: Path) -> None:
    eve_file = tmp_path / "eve.json"
    eve_file.write_text(
        "\n".join(
            [
                '{"timestamp":"2026-10-08T10:20:11+00:00","event_type":"alert","src_ip":"999.1.1.1","dest_ip":"198.51.100.20","proto":"TCP","alert":{"severity":2}}',
                '{"timestamp":"2026-10-08T10:20:12+00:00","event_type":"flow"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    service = NidsService()
    summary = service.validate_eve_file(eve_file)

    assert summary.valid_json == 2
    assert summary.invalid_json == 0
    assert summary.alert_events == 1
    assert summary.invalid_alert_payloads == 1
    assert summary.normalized_alerts == 0


def test_collector_uses_streaming_iteration_not_readall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = [
        '{"timestamp":"2026-10-08T10:20:11+00:00","event_type":"flow"}\n',
        '{"timestamp":"2026-10-08T10:20:12+00:00","event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20","proto":"TCP","alert":{"severity":2}}\n',
    ]

    class FakeHandle:
        def __enter__(self) -> FakeHandle:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def __iter__(self) -> Iterator[str]:
            return iter(lines)

        def read(self, *_args: object, **_kwargs: object) -> str:
            raise AssertionError("read() should not be used")

        def readlines(self, *_args: object, **_kwargs: object) -> list[str]:
            raise AssertionError("readlines() should not be used")

    def fake_open(self: Path, *args: object, **kwargs: object) -> FakeHandle:
        return FakeHandle()

    monkeypatch.setattr(Path, "open", fake_open)

    collector = SuricataEveCollector()
    records = list(collector.iter_records(Path("dummy.json")))

    assert len(records) == 2
    assert records[1].event_type == "alert"


def test_follow_alerts_filters_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = SuricataEveCollector()
    record = collector._parse_line(
        '{"timestamp":"2026-10-08T10:20:11+00:00","event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20","proto":"TCP","alert":{"severity":1,"signature":"x","signature_id":10}}',
        1,
    )

    class FakeCollector:
        def follow_records(
            self, *args: object, **kwargs: object
        ) -> Iterator[EveRecord]:
            yield record

        def iter_records(self, *args: object, **kwargs: object) -> Iterator[EveRecord]:
            return iter(())

    service = NidsService(collector=FakeCollector())  # type: ignore[arg-type]
    alerts = list(
        service.follow_alerts(
            Path("ignored"),
            filters=AlertFilters(severity=AlertSeverity.CRITICAL),
        )
    )

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
