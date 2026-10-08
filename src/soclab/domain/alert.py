from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class AlertSeverity(StrEnum):
    """Internal severity scale shared by all event sources."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityAlert(BaseModel):
    """Source-agnostic security alert used by Stage 2 services and CLI."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str
    timestamp: datetime
    source: str = "suricata"
    event_type: str = "alert"
    severity: AlertSeverity

    src_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)

    dst_ip: IPvAnyAddress | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)

    protocol: str | None = None

    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None

    flow_id: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("timestamp must be timezone-aware")
        return value
