from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

from soclab.collectors.suricata import EveRecord, SuricataEveCollector
from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.normalizers.suricata import normalize_suricata_alert

LOGGER = logging.getLogger(__name__)

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True)
class NidsStatus:
    enabled: bool
    eve_path: Path
    file_found: bool
    readable: bool
    size_bytes: int | None
    last_modification: datetime | None


@dataclass
class AlertFilters:
    limit: int | None = None
    severity: AlertSeverity | None = None
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None


@dataclass
class EveValidationSummary:
    path: Path
    total_lines: int = 0
    valid_json: int = 0
    invalid_json: int = 0
    alert_events: int = 0
    ignored_events: int = 0
    normalized_alerts: int = 0
    invalid_alert_payloads: int = 0
    alerts: list[SecurityAlert] = field(default_factory=list)

    @property
    def validation_passed(self) -> bool:
        return self.total_lines > 0 and self.valid_json > 0


@dataclass(frozen=True)
class WazuhIntegrationStatus:
    config_path: Path | None
    config_found: bool
    eve_configured: bool
    json_log_format_configured: bool


class NidsService:
    """Coordinates Suricata file parsing, normalization and filtering."""

    def __init__(self, *, collector: SuricataEveCollector | None = None) -> None:
        self._collector = collector or SuricataEveCollector()

    @staticmethod
    def demo_eve_path(project_root: Path) -> Path:
        return project_root / "tests" / "fixtures" / "suricata" / "eve.json"

    def status(self, *, enabled: bool, eve_path: Path) -> NidsStatus:
        file_found = eve_path.is_file()
        readable = False
        size_bytes: int | None = None
        modified_at: datetime | None = None

        if file_found:
            try:
                stat = eve_path.stat()
                size_bytes = stat.st_size
                modified_at = datetime.fromtimestamp(stat.st_mtime).astimezone()
                with eve_path.open("r", encoding="utf-8"):
                    readable = True
            except OSError:
                LOGGER.warning("Could not access EVE file: %s", eve_path)

        return NidsStatus(
            enabled=enabled,
            eve_path=eve_path,
            file_found=file_found,
            readable=readable,
            size_bytes=size_bytes,
            last_modification=modified_at,
        )

    def validate_eve_file(
        self,
        eve_path: Path,
        *,
        collect_alerts: bool = False,
    ) -> EveValidationSummary:
        summary = EveValidationSummary(path=eve_path)

        for record in self._collector.iter_records(eve_path):
            self._consume_record(
                summary=summary,
                record=record,
                collect_alerts=collect_alerts,
            )

        return summary

    def iter_alerts(
        self,
        eve_path: Path,
        *,
        filters: AlertFilters | None = None,
    ) -> Iterator[SecurityAlert]:
        active_filters = filters or AlertFilters()

        for record in self._collector.iter_records(eve_path):
            alert = self._normalize_record_to_alert(record)
            if alert is None:
                continue
            if self._matches_filters(alert=alert, filters=active_filters):
                yield alert

    def list_alerts(
        self,
        eve_path: Path,
        *,
        filters: AlertFilters | None = None,
    ) -> list[SecurityAlert]:
        active_filters = filters or AlertFilters()
        limit = active_filters.limit

        if limit is not None and limit > 0:
            last_items: deque[SecurityAlert] = deque(maxlen=limit)
            for alert in self.iter_alerts(eve_path, filters=active_filters):
                last_items.append(alert)
            return list(last_items)

        return list(self.iter_alerts(eve_path, filters=active_filters))

    def follow_alerts(
        self,
        eve_path: Path,
        *,
        filters: AlertFilters | None = None,
        poll_interval_seconds: float = 0.4,
        start_at_end: bool = False,
    ) -> Iterator[SecurityAlert]:
        active_filters = filters or AlertFilters()

        for record in self._collector.follow_records(
            eve_path,
            poll_interval_seconds=poll_interval_seconds,
            start_at_end=start_at_end,
        ):
            alert = self._normalize_record_to_alert(record)
            if alert is None:
                continue
            if self._matches_filters(alert=alert, filters=active_filters):
                yield alert

    def check_wazuh_integration(
        self,
        *,
        eve_path: Path,
        ossec_conf_path: Path | None = None,
    ) -> WazuhIntegrationStatus:
        config_path = ossec_conf_path or self._find_ossec_conf()
        if config_path is None:
            return WazuhIntegrationStatus(
                config_path=config_path,
                config_found=False,
                eve_configured=False,
                json_log_format_configured=False,
            )

        try:
            config_exists = config_path.is_file()
        except OSError:
            config_exists = False

        if not config_exists:
            return WazuhIntegrationStatus(
                config_path=config_path,
                config_found=False,
                eve_configured=False,
                json_log_format_configured=False,
            )

        try:
            content = config_path.read_text(encoding="utf-8")
        except OSError:
            LOGGER.warning("Could not read Wazuh ossec.conf: %s", config_path)
            return WazuhIntegrationStatus(
                config_path=config_path,
                config_found=False,
                eve_configured=False,
                json_log_format_configured=False,
            )

        eve_value = str(eve_path)
        eve_configured = f"<location>{eve_value}</location>" in content
        json_configured = "<log_format>json</log_format>" in content

        return WazuhIntegrationStatus(
            config_path=config_path,
            config_found=True,
            eve_configured=eve_configured,
            json_log_format_configured=json_configured,
        )

    def _consume_record(
        self,
        *,
        summary: EveValidationSummary,
        record: EveRecord,
        collect_alerts: bool,
    ) -> None:
        summary.total_lines += 1

        if not record.valid_json:
            summary.invalid_json += 1
            return

        summary.valid_json += 1

        if record.event_type != "alert":
            summary.ignored_events += 1
            return

        summary.alert_events += 1
        alert = self._normalize_record_to_alert(record)
        if alert is None:
            summary.invalid_alert_payloads += 1
            return

        summary.normalized_alerts += 1
        if collect_alerts:
            summary.alerts.append(alert)

    def _normalize_record_to_alert(self, record: EveRecord) -> SecurityAlert | None:
        if record.event is None:
            return None
        return normalize_suricata_alert(record.event)

    def _matches_filters(self, *, alert: SecurityAlert, filters: AlertFilters) -> bool:
        severity_ok = filters.severity is None or alert.severity == filters.severity
        src_ok = filters.src_ip is None or (
            alert.src_ip is not None and str(alert.src_ip) == str(filters.src_ip)
        )
        dst_ok = filters.dst_ip is None or (
            alert.dst_ip is not None and str(alert.dst_ip) == str(filters.dst_ip)
        )
        return severity_ok and src_ok and dst_ok

    def _find_ossec_conf(self) -> Path | None:
        candidates = [
            Path("/var/ossec/etc/ossec.conf"),
            Path("/opt/ossec/etc/ossec.conf"),
            Path("C:/Program Files (x86)/ossec-agent/ossec.conf"),
        ]
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue
        return None


def parse_ip_filter(value: str | None) -> IPAddress | None:
    return None if value is None else ip_address(value)


def format_size(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{num_bytes} B"
