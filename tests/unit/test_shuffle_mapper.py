from __future__ import annotations

import pytest

from soclab.domain.alert import AlertSeverity
from soclab.exceptions import AlertMappingError
from soclab.normalizers.shuffle import map_shuffle_alert


def test_canonical_payload_is_mapped_unchanged() -> None:
    alert = map_shuffle_alert(
        {
            "alert_id": "canonical-1",
            "timestamp": "2026-01-01T12:00:00Z",
            "source": "suricata",
            "severity": "HIGH",
            "src_ip": "203.0.113.7",
            "dst_ip": "10.0.0.10",
            "signature": "ET SCAN",
            "signature_id": 2001219,
        }
    )

    assert alert.alert_id == "canonical-1"
    assert alert.severity is AlertSeverity.HIGH
    assert str(alert.src_ip) == "203.0.113.7"
    assert alert.signature_id == 2001219
    assert alert.timestamp.tzinfo is not None


def test_wazuh_shuffle_wrapper_is_unwrapped() -> None:
    alert = map_shuffle_alert(
        {
            "execution_id": "exec-1",
            "alert": {
                "timestamp": "2026-01-01T12:00:00.000+0000",
                "rule": {"id": "5712", "level": 13, "description": "SSH brute force"},
                "srcip": "198.51.100.23",
                "dstip": "10.0.0.10",
            },
        }
    )

    assert alert.severity is AlertSeverity.CRITICAL
    assert alert.signature == "SSH brute force"
    assert alert.signature_id == 5712
    assert str(alert.src_ip) == "198.51.100.23"
    # Missing alert_id is derived deterministically, so dedup still works.
    assert alert.alert_id.startswith("shuffle-")


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (0, AlertSeverity.LOW),
        (3, AlertSeverity.LOW),
        (4, AlertSeverity.MEDIUM),
        (8, AlertSeverity.HIGH),
        (12, AlertSeverity.CRITICAL),
        (15, AlertSeverity.CRITICAL),
    ],
)
def test_wazuh_levels_map_to_severities(level: int, expected: AlertSeverity) -> None:
    alert = map_shuffle_alert({"alert_id": f"lvl-{level}", "level": level})

    assert alert.severity is expected


def test_epoch_milliseconds_timestamp_is_accepted() -> None:
    alert = map_shuffle_alert({"alert_id": "epoch-1", "severity": "LOW", "time": 1767225600000})

    assert alert.timestamp.year == 2026


def test_missing_severity_is_rejected() -> None:
    with pytest.raises(AlertMappingError):
        map_shuffle_alert({"alert_id": "no-severity", "src_ip": "203.0.113.1"})


def test_invalid_payload_reports_field_errors() -> None:
    with pytest.raises(AlertMappingError) as excinfo:
        map_shuffle_alert({"alert_id": "bad-timestamp", "severity": "HIGH", "time": "yesterday"})

    assert "timestamp" in str(excinfo.value)
