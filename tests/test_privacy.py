from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from legitifier_pkg.feedback.export import _get_or_create_salt, export_jsonl
from legitifier_pkg.feedback.store import FeedbackStore


def _make_store(tmp_path: Path) -> FeedbackStore:
    return FeedbackStore(db_path=tmp_path / "scans.db")


def _save_scan_with_login(store: FeedbackStore, login: str) -> int:
    from legitifier_pkg.core.models import ScanReport, Verdict

    report = ScanReport(
        repo_url=f"https://github.com/{login}/some-repo",
        risk_score=20.0,
        verdict=Verdict.CLEAN,
        results=[],
    )
    return store.save_scan(report)


def test_forget_removes_reputation_entries(tmp_path):
    store = _make_store(tmp_path)
    store.save_reputation("owner", "SUSPICIOUS", confidence="probable", login="alice")
    counts = store.forget_login("alice")
    assert counts["reputation"] == 1


def test_forget_cascades_to_feedback(tmp_path):
    from legitifier_pkg.core.models import Verdict

    store = _make_store(tmp_path)
    scan_id = _save_scan_with_login(store, "alice")
    store.save_feedback(scan_id, Verdict.CLEAN)

    counts = store.forget_login("alice")
    assert counts["scans"] == 1
    assert counts["feedback"] == 1


def test_forget_idempotent(tmp_path):
    store = _make_store(tmp_path)
    counts = store.forget_login("nonexistent")
    assert all(v == 0 for v in counts.values())


def test_forget_deep_scrubs_report_json(tmp_path):
    store = _make_store(tmp_path)
    _save_scan_with_login(store, "alice")
    counts = store.forget_login_deep("alice")
    assert counts["reports_scrubbed"] >= 1


def test_anonymize_export_replaces_owner_in_url(tmp_path):
    store = _make_store(tmp_path)
    scan_id = _save_scan_with_login(store, "realuser")
    from legitifier_pkg.core.models import Verdict

    store.save_feedback(scan_id, Verdict.CLEAN)

    out = tmp_path / "out.jsonl"
    with patch(
        "legitifier_pkg.feedback.export._SALT_PATH", tmp_path / "anonymize_salt"
    ):
        export_jsonl(out, store=store, anonymize=True)

    lines = out.read_text().splitlines()
    assert lines
    row = json.loads(lines[0])
    assert "realuser" not in row["repo_url"]


def test_anonymize_salt_is_stable(tmp_path):
    with patch(
        "legitifier_pkg.feedback.export._SALT_PATH", tmp_path / "anonymize_salt"
    ):
        s1 = _get_or_create_salt()
        s2 = _get_or_create_salt()
    assert s1 == s2
    assert len(s1) == 32


def test_export_without_anonymize_unchanged(tmp_path):
    store = _make_store(tmp_path)
    scan_id = _save_scan_with_login(store, "realuser")
    from legitifier_pkg.core.models import Verdict

    store.save_feedback(scan_id, Verdict.CLEAN)

    out = tmp_path / "out.jsonl"
    export_jsonl(out, store=store, anonymize=False)

    lines = out.read_text().splitlines()
    assert lines
    row = json.loads(lines[0])
    assert "realuser" in row["repo_url"]
