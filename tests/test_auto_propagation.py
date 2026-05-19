from pathlib import Path

import pytest

from legitifier_pkg.data.loader import ReputationStore
from legitifier_pkg.feedback.store import FeedbackStore


def _make_store(tmp_path: Path) -> FeedbackStore:
    return FeedbackStore(db_path=tmp_path / "scans.db")


def _make_report(tmp_path, risk_score: float, flagged_logins: list[str]):
    from unittest.mock import MagicMock

    from legitifier_pkg.core.models import HeuristicResult, ScanReport, Verdict

    verdict = (
        Verdict.SCAM
        if risk_score >= 75
        else Verdict.LIKELY_SCAM
        if risk_score >= 50
        else Verdict.CLEAN
    )

    contrib_result = MagicMock(spec=HeuristicResult)
    contrib_result.heuristic_id = "contributor_reputation"
    contrib_result.triggered = bool(flagged_logins)
    contrib_result.score = 70.0 if flagged_logins else 0.0
    contrib_result.raw_data = {
        "flagged_logins": [{"login": login} for login in flagged_logins],
        "sample_size": 5,
    }
    contrib_result.evidence = "test"
    contrib_result.severity = MagicMock()
    contrib_result.severity.value = "high"

    report = MagicMock(spec=ScanReport)
    report.repo_url = "github.com/scammer/badrepo"
    report.risk_score = risk_score
    report.verdict = verdict
    report.results = [contrib_result]
    return report


def test_auto_propagated_entry_has_unsure_confidence(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report(tmp_path, risk_score=80.0, flagged_logins=["bad_actor"])
    store.record_contributor_reputation(report)

    rep_store = ReputationStore(seed_path=tmp_path / "empty.jsonl", db_path=store.path)
    entry = rep_store.lookup("bad_actor")
    assert entry is not None
    assert entry.confidence.value == "unsure"
    assert entry.source == "auto"


def test_auto_propagated_entry_does_not_penalize_future_scans(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report(tmp_path, risk_score=80.0, flagged_logins=["bad_actor"])
    store.record_contributor_reputation(report)

    rep_store = ReputationStore(seed_path=tmp_path / "empty.jsonl", db_path=store.path)
    assert rep_store.score("bad_actor") == 0.0


def test_manual_feedback_entry_is_not_gated(tmp_path):
    """Entries added via save_reputation (human feedback) keep their confidence."""
    store = _make_store(tmp_path)
    store.save_reputation(
        entry_type="owner",
        verdict="SCAM",
        confidence="probable",
        login="bad_actor",
        source="user",
    )

    rep_store = ReputationStore(seed_path=tmp_path / "empty.jsonl", db_path=store.path)
    entry = rep_store.lookup("bad_actor")
    assert entry is not None
    assert entry.confidence.value == "probable"
    assert rep_store.score("bad_actor") == pytest.approx(54.0)  # 90 * 0.6
