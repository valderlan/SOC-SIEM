"""Forensic evidence capture for HIGH and CRITICAL security alerts."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from soclab.domain.alert import SecurityAlert

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(alert_id: str) -> str:
    cleaned = _UNSAFE_CHARS.sub("_", alert_id).strip("._")
    return (cleaned or "alert")[:80]


class EvidenceCollector:
    """Persists raw alert and response context JSON files for incident investigation."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def save(
        self,
        alert: SecurityAlert,
        *,
        action: str,
        requested_action: str,
        target_ip: str | None,
        executed: bool,
        dry_run: bool,
        protected: bool,
        adapter: str,
        reason: str,
    ) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{_safe_filename(alert.alert_id)}.json"
        payload = {
            "captured_at": datetime.now(UTC).isoformat(),
            "alert": alert.model_dump(mode="json"),
            "response": {
                "action": action,
                "requested_action": requested_action,
                "target_ip": target_ip,
                "executed": executed,
                "dry_run": dry_run,
                "protected": protected,
                "adapter": adapter,
                "reason": reason,
            },
        }
        path.write_text(
            json.dumps(payload, indent=2, default=str, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def is_writable(self) -> bool:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            probe = self.directory / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except OSError:
            return False
