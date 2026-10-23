"""SQLite-backed alert deduplication (standard library only)."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path


class AlertDeduplicator:
    """Remembers alert_id values so repeated webhook deliveries are ignored."""

    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS processed_alerts ("
                "alert_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=5)

    def is_duplicate(self, alert_id: str) -> bool:
        """Register alert_id and report whether it had already been processed."""
        # shortcut: rows are kept forever; add a TTL purge if the lab runs for months.
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO processed_alerts (alert_id, first_seen) "
                "VALUES (?, ?)",
                (alert_id, datetime.now(UTC).isoformat()),
            )
            return cursor.rowcount == 0

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT COUNT(*) FROM processed_alerts").fetchone()
        return int(row[0]) if row is not None else 0

    def is_writable(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.execute("SELECT 1 FROM processed_alerts LIMIT 1").fetchall()
        except (OSError, sqlite3.Error):
            return False
        return True
