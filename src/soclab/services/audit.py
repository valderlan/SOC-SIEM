"""Append-only JSONL audit trail for response decisions."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """Writes one JSON line per alert decision to logs/audit.jsonl."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, event: Mapping[str, Any]) -> None:
        payload = {"timestamp": datetime.now(UTC).isoformat(), **event}
        line = json.dumps(payload, default=str, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def is_writable(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8"):
                return True
        except OSError:
            return False
