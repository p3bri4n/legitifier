from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path

from legitifier_pkg.feedback.store import FeedbackStore

_SALT_PATH = Path.home() / ".legitifier" / "anonymize_salt"


def _get_or_create_salt() -> bytes:
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    new_salt = secrets.token_bytes(32)
    _SALT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SALT_PATH.write_bytes(new_salt)
    _SALT_PATH.chmod(0o600)
    return new_salt


def _hash_login(login: str, salt: bytes) -> str:
    return hashlib.sha256(salt + login.encode()).hexdigest()[:16]


def _anonymize_row(row: dict, salt: bytes) -> dict:
    row = dict(row)
    url = row.get("repo_url", "")
    m = re.match(r"(https?://)?github\.com/([^/]+)/(.+)", url)
    if m:
        row["repo_url"] = f"github.com/{_hash_login(m.group(2), salt)}/{m.group(3)}"
    return row


def export_jsonl(
    output: Path, store: FeedbackStore | None = None, anonymize: bool = False
) -> int:
    """Export annotated scans as JSONL for model training. Returns record count."""
    salt = _get_or_create_salt() if anonymize else None
    store = store or FeedbackStore()
    records = store.export_annotated()

    with output.open("w") as f:
        for record in records:
            risk_score = record.scan_report.risk_score
            row = {
                "repo_url": record.repo_url,
                "risk_score": risk_score,
                "auto_verdict": record.scan_report.verdict.value,
                "user_verdict": record.user_verdict.value,
                "confidence": record.confidence.value,
                "note": record.note,
                "scanner_version": record.scan_report.scanner_version,
                "scanned_at": record.scan_report.scanned_at.isoformat(),
                "readme": next(
                    (
                        r.raw_data.get("readme", "")
                        for r in record.scan_report.results
                        if "readme" in r.raw_data
                    ),
                    "",
                ),
                "heuristic_scores": {
                    r.heuristic_id: r.score for r in record.scan_report.results
                },
                "heuristic_triggered": {
                    r.heuristic_id: r.triggered for r in record.scan_report.results
                },
            }
            if anonymize and salt is not None:
                row = _anonymize_row(row, salt)
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return len(records)
