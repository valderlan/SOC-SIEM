from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    ValidationError,
    field_validator,
)

LOGGER = logging.getLogger(__name__)


class SuricataAlertData(BaseModel):

    model_config = ConfigDict(extra="ignore")

    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None
    severity: int | None = None


class SuricataEvent(BaseModel):

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    event_type: str
    flow_id: int | None = None

    src_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)

    dest_ip: IPvAnyAddress | None = None
    dest_port: int | None = Field(default=None, ge=0, le=65535)

    proto: str | None = None
    alert: SuricataAlertData | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> SuricataEvent:
        event = cls.model_validate(payload)
        return event.model_copy(update={"raw": payload})


@dataclass(frozen=True)
class EveRecord:

    line_number: int
    raw_line: str
    valid_json: bool
    payload: dict[str, Any] | None
    event: SuricataEvent | None
    error: str | None = None

    @property
    def event_type(self) -> str | None:
        if self.payload is None:
            return None
        value = self.payload.get("event_type")
        if value is None:
            return None
        return str(value)


class SuricataEveCollector:
    """Reads Suricata EVE files safely without loading the whole file in memory."""

    def iter_records(self, eve_path: Path) -> Iterator[EveRecord]:
        with eve_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                yield self._parse_line(line, line_number)

    def follow_records(
        self,
        eve_path: Path,
        *,
        poll_interval_seconds: float = 0.4,
        start_at_end: bool = False,
    ) -> Iterator[EveRecord]:
        line_number = 0
        with eve_path.open("r", encoding="utf-8") as handle:
            if start_at_end:
                handle.seek(0, 2)

            while True:
                position = handle.tell()
                raw_line = handle.readline()

                if not raw_line:
                    time.sleep(poll_interval_seconds)
                    continue

                if not raw_line.endswith("\n"):

                    handle.seek(position)
                    time.sleep(poll_interval_seconds)
                    continue

                line_number += 1
                line = raw_line.strip()
                if not line:
                    continue
                yield self._parse_line(line, line_number)

    def _parse_line(self, raw_line: str, line_number: int) -> EveRecord:
        try:
            payload_raw = json.loads(raw_line)
        except json.JSONDecodeError:
            LOGGER.warning("Invalid JSON in EVE line %s", line_number)
            return EveRecord(
                line_number=line_number,
                raw_line=raw_line,
                valid_json=False,
                payload=None,
                event=None,
                error="invalid-json",
            )

        if not isinstance(payload_raw, dict):
            LOGGER.warning("Unsupported EVE payload type in line %s", line_number)
            return EveRecord(
                line_number=line_number,
                raw_line=raw_line,
                valid_json=False,
                payload=None,
                event=None,
                error="json-root-not-object",
            )

        payload = payload_raw
        try:
            event = SuricataEvent.from_payload(payload)
        except ValidationError:
            LOGGER.warning("Invalid EVE event schema in line %s", line_number)
            return EveRecord(
                line_number=line_number,
                raw_line=raw_line,
                valid_json=True,
                payload=payload,
                event=None,
                error="invalid-event-schema",
            )

        return EveRecord(
            line_number=line_number,
            raw_line=raw_line,
            valid_json=True,
            payload=payload,
            event=event,
            error=None,
        )
