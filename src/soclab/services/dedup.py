"""SQLite-backed alert deduplication (standard library only)."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _parse_iso_utc(raw: str) -> datetime | None:
    text = raw.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class AlertDeduplicator:
    """Remembers alert_id values so repeated webhook deliveries are ignored."""

    def __init__(self, db_path: Path, *, ttl_seconds: float = 0.0) -> None:
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self.path = Path(db_path)
        self.ttl_seconds = float(ttl_seconds)
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
        now = datetime.now(UTC)
        with closing(self._connect()) as connection, connection:
            if self.ttl_seconds > 0:
                self._purge_on_connection(connection, self.ttl_seconds, now=now)
            cursor = connection.execute(
                "INSERT OR IGNORE INTO processed_alerts (alert_id, first_seen) "
                "VALUES (?, ?)",
                (alert_id, now.isoformat()),
            )
            return cursor.rowcount == 0

    def purge_older_than(
        self,
        ttl_seconds: float,
        *,
        now: datetime | None = None,
    ) -> int:
        """Delete processed alert records older than ttl_seconds; return deleted count."""
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        reference = (now or datetime.now(UTC)).astimezone(UTC)
        with closing(self._connect()) as connection, connection:
            return self._purge_on_connection(connection, ttl_seconds, now=reference)

    def clear(self) -> int:
        """Delete all entries from the deduplication table; return deleted count."""
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM processed_alerts")
            return cursor.rowcount if cursor.rowcount >= 0 else 0

    def _purge_on_connection(
        self,
        connection: sqlite3.Connection,
        ttl_seconds: float,
        *,
        now: datetime,
    ) -> int:
        cutoff = now - timedelta(seconds=ttl_seconds)
        rows = connection.execute(
            "SELECT alert_id, first_seen FROM processed_alerts"
        ).fetchall()
        expired: list[tuple[str]] = []
        for alert_id, first_seen in rows:
            parsed = _parse_iso_utc(str(first_seen))
            if parsed is not None and parsed <= cutoff:
                expired.append((str(alert_id),))
        if not expired:
            return 0
        connection.executemany(
            "DELETE FROM processed_alerts WHERE alert_id = ?",
            expired,
        )
        return len(expired)

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
