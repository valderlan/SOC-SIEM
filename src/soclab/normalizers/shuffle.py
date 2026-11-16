"""Map arbitrary Shuffle/Wazuh webhook payloads into the canonical SecurityAlert."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from soclab.domain.alert import AlertSeverity, SecurityAlert
from soclab.exceptions import AlertMappingError
from soclab.normalizers.suricata import normalize_suricata_severity

_WRAPPER_KEYS = ("all_fields", "alert", "data", "event")

_TEXT_SEVERITIES = {
    "LOW": AlertSeverity.LOW,
    "INFO": AlertSeverity.LOW,
    "INFORMATIONAL": AlertSeverity.LOW,
    "MEDIUM": AlertSeverity.MEDIUM,
    "WARNING": AlertSeverity.MEDIUM,
    "WARN": AlertSeverity.MEDIUM,
    "HIGH": AlertSeverity.HIGH,
    "ERROR": AlertSeverity.HIGH,
    "CRITICAL": AlertSeverity.CRITICAL,
    "CRIT": AlertSeverity.CRITICAL,
    "SEVERE": AlertSeverity.CRITICAL,
}


def map_shuffle_alert(payload: Mapping[str, Any]) -> SecurityAlert:
    """Build a SecurityAlert from a Shuffle webhook body.

    Accepts the canonical SOC Lab payload, Wazuh alert JSON and Shuffle
    wrappers (``{"alert": {...}}``). Raises AlertMappingError when the body
    cannot be understood, never silently downgrading the severity.
    """
    data = _unwrap(payload)
    try:
        return SecurityAlert.model_validate(_alert_fields(data))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'payload'}: {error['msg']}"
            for error in exc.errors()
        )
        raise AlertMappingError(f"invalid alert payload ({problems})") from exc


def _unwrap(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    current: Mapping[str, Any] = payload
    for _ in range(2):
        unwrapped = False
        for key in _WRAPPER_KEYS:
            nested = current.get(key)
            if isinstance(nested, Mapping):
                # Wazuh's native shuffle.py compresses severity into 1/2/3 at the outer
                # level while keeping the real 0-15 rule.level inside all_fields.
                base = (
                    {k: v for k, v in current.items() if k != "severity"}
                    if key == "all_fields" and isinstance(nested.get("rule"), Mapping)
                    else current
                )
                # The nested alert wins; wrapper keys only fill the gaps.
                current = {**base, **nested}
                if key == "data":
                    return current
                unwrapped = True
                break
        if not unwrapped:
            break
    return current


def _alert_fields(data: Mapping[str, Any]) -> dict[str, Any]:
    rule = _mapping(data.get("rule"))
    nested_data = _mapping(data.get("data"))
    nested_alert = _mapping(nested_data.get("alert"))
    sources = (data, nested_data)

    default_source = "wazuh" if rule or _mapping(data.get("agent")) else "shuffle"
    return {
        "alert_id": _alert_id(data),
        "timestamp": _timestamp(_first(data, ("timestamp", "time", "@timestamp", "date"))),
        "source": _text(_first(data, ("source", "sensor"))) or default_source,
        "event_type": _text(_first(data, ("event_type", "event"))) or "alert",
        "severity": _severity(data, rule, nested_alert),
        "src_ip": _first_in(sources, ("src_ip", "srcip", "source_ip", "src_addr")),
        "src_port": _first_in(sources, ("src_port", "srcport", "source_port")),
        "dst_ip": _first_in(
            sources, ("dst_ip", "dstip", "dest_ip", "destination_ip")
        ),
        "dst_port": _first_in(
            sources, ("dst_port", "dstport", "dest_port", "destination_port")
        ),
        "protocol": _text(_first_in(sources, ("protocol", "proto"))),
        "signature": _text(
            _first(data, ("signature", "description", "rule_description", "message"))
        )
        or _text(nested_alert.get("signature"))
        or _text(rule.get("description")),
        "signature_id": _signature_id(data, rule, nested_alert),
        "category": _text(_first(data, ("category", "rule_group")))
        or _text(nested_alert.get("category"))
        or _text(rule.get("groups")),
        "flow_id": _first_in(sources, ("flow_id", "flow")),
        "raw": dict(data),
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(data: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _first_in(
    mappings: tuple[Mapping[str, Any], ...], keys: tuple[str, ...]
) -> Any:
    for mapping in mappings:
        found = _first(mapping, keys)
        if found is not None:
            return found
    return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or None
    text = str(value).strip()
    return text or None


def _alert_id(data: Mapping[str, Any]) -> str:
    explicit = _text(_first(data, ("alert_id", "alertId", "event_id", "id")))
    if explicit is not None:
        return explicit
    # Deterministic id keeps deduplication working when the source omits one.
    digest = hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"shuffle-{digest}"


def _signature_id(
    data: Mapping[str, Any],
    rule: Mapping[str, Any],
    nested_alert: Mapping[str, Any] | None = None,
) -> int | None:
    raw = _first(data, ("signature_id", "sid"))
    if raw is None and nested_alert:
        raw = _first(nested_alert, ("signature_id", "sid"))
    if raw is None:
        raw = _first(data, ("rule_id",))
    if raw is None:
        raw = _first(rule, ("id", "sid", "signature_id"))
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def _severity(
    data: Mapping[str, Any],
    rule: Mapping[str, Any],
    nested_alert: Mapping[str, Any] | None = None,
) -> str:
    raw = _first(data, ("severity", "level", "risk", "priority"))
    if raw is None:
        raw = _first(rule, ("level", "severity"))
    if raw is None and nested_alert and nested_alert.get("severity") is not None:
        try:
            return normalize_suricata_severity(int(str(nested_alert["severity"]))).value
        except ValueError:
            pass
    if raw is None:
        raise AlertMappingError("alert payload has no severity/level field")
    if isinstance(raw, str):
        text = raw.strip().upper()
        if text in _TEXT_SEVERITIES:
            return _TEXT_SEVERITIES[text].value
    try:
        return _severity_from_level(float(str(raw).strip())).value
    except ValueError as exc:
        raise AlertMappingError(f"unsupported severity value: {raw}") from exc


def _severity_from_level(level: float) -> AlertSeverity:
    """Interpret numeric levels on the Wazuh 0-15 scale."""
    if level >= 12:
        return AlertSeverity.CRITICAL
    if level >= 8:
        return AlertSeverity.HIGH
    if level >= 4:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def _timestamp(raw: Any) -> datetime:
    value: datetime
    if isinstance(raw, datetime):
        value = raw
    elif isinstance(raw, (int, float)):
        seconds = raw / 1000 if raw > 1e11 else raw
        value = datetime.fromtimestamp(seconds, tz=UTC)
    elif isinstance(raw, str) and raw.strip():
        try:
            value = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise AlertMappingError(f"invalid timestamp: {raw}") from exc
    else:
        return datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value
