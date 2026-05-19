from __future__ import annotations

import json
import sqlite3
import time
from datetime import date, datetime
from pathlib import Path
from typing import Any

_CACHE_PATH = Path.home() / ".legitifier" / "cache.db"
_DEFAULT_TTL = 6 * 3600  # 6 hours

_DT_PREFIX = "__dt__:"
_DATE_PREFIX = "__date__:"


def _serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return f"{_DT_PREFIX}{obj.isoformat()}"
    if isinstance(obj, date):
        return f"{_DATE_PREFIX}{obj.isoformat()}"
    raise TypeError(f"Not serializable: {type(obj)}")


def _deserialize(obj: Any) -> Any:
    if isinstance(obj, str):
        if obj.startswith(_DT_PREFIX):
            return datetime.fromisoformat(obj[len(_DT_PREFIX) :])
        if obj.startswith(_DATE_PREFIX):
            return date.fromisoformat(obj[len(_DATE_PREFIX) :])
    if isinstance(obj, dict):
        return {k: _deserialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deserialize(v) for v in obj]
    return obj


class FetchCache:
    """
    Simple SQLite-backed cache for GitHub API responses.
    Keyed by repo slug, with a configurable TTL.
    Handles datetime/date serialization transparently.
    """

    def __init__(self, path: Path = _CACHE_PATH, ttl: int = _DEFAULT_TTL) -> None:
        self._path = path
        self._ttl = ttl
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key       TEXT PRIMARY KEY,
                    value     TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)

    def get(self, key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value, cached_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        value, cached_at = row
        if time.time() - cached_at > self._ttl:
            self.delete(key)
            return None
        raw = json.loads(value)
        return _deserialize(raw)

    def set(self, key: str, value: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, cached_at) VALUES (?, ?, ?)",
                (key, json.dumps(value, default=_serialize), time.time()),
            )

    def delete(self, key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns count deleted."""
        cutoff = time.time() - self._ttl
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM cache WHERE cached_at < ?", (cutoff,))
            return cur.rowcount
