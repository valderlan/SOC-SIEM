from __future__ import annotations

import hashlib
import json

from soclab.collectors.suricata import SuricataEvent
from soclab.domain.alert import AlertSeverity, SecurityAlert


def normalize_suricata_severity(severity: int | None) -> AlertSeverity:
    """Map Suricata numeric severity into the internal enum.

    Suricata alert severity commonly uses lower numbers for higher priority.
    Mapping used by this project:
      1 -> CRITICAL
      2 -> HIGH
      3 -> MEDIUM
      >=4 or missing -> LOW
    """

    if severity is None:
        return AlertSeverity.LOW
    if severity <= 1:
        return AlertSeverity.CRITICAL
    if severity == 2:
        return AlertSeverity.HIGH
    if severity == 3:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def normalize_suricata_alert(event: SuricataEvent) -> SecurityAlert | None:
    """Convert a Suricata alert event to a canonical SecurityAlert."""

    if event.event_type.lower() != "alert":
        return None

    alert_data = event.alert
    raw_json = json.dumps(event.raw, sort_keys=True, default=str)
    digest = hashlib.sha1(raw_json.encode("utf-8")).hexdigest()[:16]

    return SecurityAlert(
        alert_id=f"suricata-{digest}",
        timestamp=event.timestamp,
        source="suricata",
        event_type="alert",
        severity=normalize_suricata_severity(
            alert_data.severity if alert_data is not None else None
        ),
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dest_ip,
        dst_port=event.dest_port,
        protocol=(event.proto.upper() if event.proto else None),
        signature=(alert_data.signature if alert_data is not None else None),
        signature_id=(alert_data.signature_id if alert_data is not None else None),
        category=(alert_data.category if alert_data is not None else None),
        flow_id=event.flow_id,
        raw=event.raw,
    )
