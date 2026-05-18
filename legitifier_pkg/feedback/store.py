from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
from pathlib import Path

from legitifier_pkg.core.models import ScanReport, Verdict
from legitifier_pkg.feedback.models import Confidence, FeedbackRecord

_DB_PATH = Path.home() / ".legitifier" / "scans.db"


def _default_db() -> Path:
    return _DB_PATH


def _anonymous_id() -> str:
    """Stable, anonymous machine fingerprint — no PII."""
    raw = platform.node() + str(os.getuid() if hasattr(os, "getuid") else "win")
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class FeedbackStore:
    def __init__(self, db_path: Path = _default_db()) -> None:
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_url    TEXT NOT NULL,
                    scanned_at  TEXT NOT NULL,
                    final_score REAL NOT NULL,
                    verdict     TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id         INTEGER NOT NULL REFERENCES scans(id),
                    user_verdict    TEXT NOT NULL,
                    confidence      TEXT NOT NULL,
                    note            TEXT,
                    submitted_at    TEXT NOT NULL,
                    user_id         TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    type        TEXT NOT NULL,
                    login       TEXT,
                    slug        TEXT,
                    verdict     TEXT NOT NULL,
                    confidence  TEXT NOT NULL DEFAULT 'probable',
                    source      TEXT NOT NULL DEFAULT 'user',
                    note        TEXT,
                    added       TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_offsets (
                    query       TEXT PRIMARY KEY,
                    offset      INTEGER NOT NULL DEFAULT 0,
                    updated_at  TEXT NOT NULL
                )
            """)

    def save_scan(self, report: ScanReport) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (repo_url, scanned_at, final_score, verdict, report_json) VALUES (?,?,?,?,?)",
                (
                    report.repo_url,
                    report.scanned_at.isoformat(),
                    report.final_score,
                    report.verdict.value,
                    report.model_dump_json(),
                ),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def save_feedback(
        self,
        scan_id: int,
        user_verdict: Verdict,
        confidence: Confidence = Confidence.PROBABLE,
        note: str | None = None,
    ) -> FeedbackRecord:
        report = self._get_report(scan_id)
        record = FeedbackRecord(
            repo_url=report.repo_url,
            scan_report=report,
            user_verdict=user_verdict,
            confidence=confidence,
            note=note,
            anonymous_user_id=_anonymous_id(),
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO feedback (scan_id, user_verdict, confidence, note, submitted_at, user_id) VALUES (?,?,?,?,?,?)",
                (
                    scan_id,
                    record.user_verdict.value,
                    record.confidence.value,
                    record.note,
                    record.submitted_at.isoformat(),
                    record.anonymous_user_id,
                ),
            )
        return record

    def _get_report(self, scan_id: int) -> ScanReport:
        with self._connect() as conn:
            row = conn.execute("SELECT report_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise KeyError(f"No scan with id={scan_id}")
        return ScanReport.model_validate(json.loads(row[0]))

    def export_annotated(self) -> list[FeedbackRecord]:
        """Return all scans that have at least one feedback entry."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT s.report_json, f.user_verdict, f.confidence, f.note, f.submitted_at, f.user_id
                FROM feedback f
                JOIN scans s ON s.id = f.scan_id
            """).fetchall()
        records = []
        for report_json, verdict, confidence, note, submitted_at, user_id in rows:
            report = ScanReport.model_validate(json.loads(report_json))
            records.append(FeedbackRecord(
                repo_url=report.repo_url,
                scan_report=report,
                user_verdict=Verdict(verdict),
                confidence=Confidence(confidence),
                note=note,
                submitted_at=submitted_at,
                anonymous_user_id=user_id,
            ))
        return records

    def save_reputation(
        self,
        entry_type: str,
        verdict: str,
        confidence: str = "probable",
        login: str | None = None,
        slug: str | None = None,
        note: str | None = None,
        source: str = "user",
    ) -> None:
        """Persist a reputation entry derived from user feedback."""
        from datetime import date
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO reputation (type, login, slug, verdict, confidence, source, note, added) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (entry_type, login, slug, verdict, confidence, source, note, date.today().isoformat()),
            )

    def recent_scans(
        self,
        limit: int = 20,
        verdict_filter: str | None = None,
    ) -> list[dict]:
        """Return most recent scan per repo, optionally filtered by verdict."""
        query = """
            SELECT id, repo_url, scanned_at, final_score, verdict
            FROM scans
            WHERE id IN (
                SELECT MAX(id) FROM scans GROUP BY repo_url
            )
        """
        params: list = []
        if verdict_filter:
            query = f"""
                SELECT id, repo_url, scanned_at, final_score, verdict
                FROM scans
                WHERE id IN (
                    SELECT MAX(id) FROM scans GROUP BY repo_url
                )
                AND verdict = ?
            """
            params.append(verdict_filter)
        query += " ORDER BY scanned_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {"id": r[0], "repo_url": r[1], "scanned_at": r[2],
             "final_score": r[3], "verdict": r[4]}
            for r in rows
        ]

    def get_recent_scan(self, repo_url: str, max_age_seconds: int) -> "ScanReport | None":
        """Return the most recent scan for a repo if within max_age_seconds, else None."""
        import json
        import time
        cutoff = time.time() - max_age_seconds
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json, scanned_at FROM scans WHERE repo_url = ? "
                "ORDER BY scanned_at DESC LIMIT 1",
                (repo_url,),
            ).fetchone()
        if not row:
            return None
        report_json, scanned_at_str = row
        # Parse scanned_at and compare
        from datetime import datetime, timezone
        try:
            scanned_at = datetime.fromisoformat(scanned_at_str)
            if scanned_at.tzinfo is None:
                scanned_at = scanned_at.replace(tzinfo=timezone.utc)
            if scanned_at.timestamp() < cutoff:
                return None
        except Exception:
            return None
        return ScanReport.model_validate(json.loads(report_json))

    def get_search_offset(self, query: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT offset FROM search_offsets WHERE query = ?", (query,)
            ).fetchone()
        return row[0] if row else 0

    def set_search_offset(self, query: str, offset: int) -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO search_offsets (query, offset, updated_at) VALUES (?, ?, ?)",
                (query, offset, now),
            )

    def reset_search_offset(self, query: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM search_offsets WHERE query = ?", (query,))
