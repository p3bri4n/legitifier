from __future__ import annotations

import pytest

from legitifier_pkg.core.models import HeuristicResult, Severity, Verdict
from legitifier_pkg.core.scorer import Scorer


def _make_result(
    heuristic_id: str,
    score: float,
    triggered: bool,
    severity: Severity,
    category: str = "social_signals",
) -> HeuristicResult:
    return HeuristicResult(
        heuristic_id=heuristic_id,
        score=score,
        triggered=triggered,
        evidence="test",
        severity=severity,
        category=category,
    )


def _high_score_results() -> list[HeuristicResult]:
    return [
        _make_result("stars_velocity", 80.0, True, Severity.HIGH),
        _make_result("fork_ratio", 70.0, True, Severity.MEDIUM),
        _make_result("no_activity", 0.0, False, Severity.HIGH),
    ]


@pytest.fixture
def scorer() -> Scorer:
    return Scorer()


def test_certain_clean_caps_at_49(scorer):
    results = _high_score_results()
    report = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "certain", "type": "owner"},
    )
    assert report.risk_score <= 49.0
    assert report.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS)
    assert any("capped" in e.lower() for e in report.errors)


def test_probable_clean_caps_at_65(scorer):
    results = _high_score_results()
    report = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "probable", "type": "owner"},
    )
    assert report.risk_score <= 65.0


def test_unsure_clean_only_minus_10(scorer):
    results = _high_score_results()
    raw = scorer.aggregate("https://github.com/owner/repo", results, [])
    with_unsure = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "unsure", "type": "owner"},
    )
    assert with_unsure.risk_score == max(raw.risk_score - 10, 0)


def test_no_whitelist_match_leaves_score_unchanged(scorer):
    results = _high_score_results()
    raw = scorer.aggregate("https://github.com/owner/repo", results, [])
    no_match = scorer.aggregate(
        "https://github.com/owner/repo", results, [], whitelist_match=None
    )
    assert raw.risk_score == no_match.risk_score


def test_critical_signals_bypass_whitelist(scorer):
    results = [
        _make_result(
            "api_disguised_as_local", 90.0, True, Severity.CRITICAL, "code_quality"
        ),
        _make_result(
            "telegram_funnel", 90.0, True, Severity.CRITICAL, "content_claims"
        ),
        _make_result("no_activity", 0.0, False, Severity.HIGH, "repo_metadata"),
    ]
    # Without whitelist
    raw = scorer.aggregate("https://github.com/owner/repo", results, [])
    # With certain whitelist — should be bypassed due to 2 critical code/content signals
    capped = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "certain", "type": "owner"},
    )
    assert capped.risk_score == raw.risk_score
    assert not any("capped" in e.lower() for e in capped.errors)


def test_single_critical_does_not_bypass(scorer):
    results = [
        _make_result(
            "api_disguised_as_local", 90.0, True, Severity.CRITICAL, "code_quality"
        ),
        _make_result("no_activity", 0.0, False, Severity.HIGH, "repo_metadata"),
    ]
    capped = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "certain", "type": "owner"},
    )
    assert capped.risk_score <= 49.0


def test_critical_from_metadata_only_does_not_bypass(scorer):
    results = [
        _make_result(
            "owner_reputation", 90.0, True, Severity.CRITICAL, "repo_metadata"
        ),
        _make_result(
            "abandoned_takeover", 90.0, True, Severity.CRITICAL, "repo_history"
        ),
    ]
    capped = scorer.aggregate(
        "https://github.com/owner/repo",
        results,
        [],
        whitelist_match={"confidence": "certain", "type": "owner"},
    )
    assert capped.risk_score <= 49.0


def test_repo_match_takes_precedence_over_owner_match():
    from legitifier_pkg.data.loader import ReputationStore
    from legitifier_pkg.data.models import (
        ReputationConfidence,
        ReputationEntry,
        ReputationVerdict,
    )
    from legitifier_pkg.fetchers.local_db import LocalDBFetcher

    store = ReputationStore.__new__(ReputationStore)
    store._entries = {}

    # Add both a repo entry (SCAM) and an owner entry (CLEAN)
    repo_entry = ReputationEntry(
        type="repo",
        slug="owner/repo",
        login=None,
        verdict=ReputationVerdict.SCAM,
        confidence=ReputationConfidence.PROBABLE,
        source="manual",
        note="bad repo",
        added="2026-05-19",
    )
    owner_entry = ReputationEntry(
        type="owner",
        login="owner",
        slug=None,
        verdict=ReputationVerdict.CLEAN,
        confidence=ReputationConfidence.CERTAIN,
        source="manual",
        note="trusted owner",
        added="2026-05-19",
    )
    store._entries["owner/repo"] = [repo_entry]
    store._entries["owner"] = [owner_entry]

    fetcher = LocalDBFetcher(store=store)
    result = fetcher._owner_rep("owner", "owner/repo")

    assert result["matched_type"] == "repo"
    assert result["verdict"] == "SCAM"


def test_no_whitelist_flag_disables_capping():
    from unittest.mock import MagicMock

    from legitifier_pkg.core.models import ScanReport
    from legitifier_pkg.pipeline import Pipeline

    results = [
        _make_result("stars_velocity", 80.0, True, Severity.HIGH),
        _make_result("fork_ratio", 70.0, True, Severity.MEDIUM),
    ]

    mock_github = MagicMock()
    mock_github.fetch.return_value = {
        "slug": "huggingface/testrepo",
        "owner_reputation": {
            "verdict": "CLEAN",
            "confidence": "certain",
            "matched_type": "owner",
            "score": 0.0,
            "note": None,
        },
    }

    mock_registry = MagicMock()
    mock_config = MagicMock()
    mock_config.category = "social_signals"
    mock_config.id = "stars_velocity"
    mock_registry.load.return_value = None
    mock_registry.all.return_value = []

    mock_scorer = MagicMock()
    captured: list[dict] = []

    def fake_aggregate(repo_url, results, errors, whitelist_match=None, duration=0.0):
        captured.append({"whitelist_match": whitelist_match})
        return ScanReport(
            repo_url=repo_url,
            risk_score=75.0,
            verdict=Verdict.SCAM,
            results=[],
        )

    mock_scorer.aggregate.side_effect = fake_aggregate
    mock_store = MagicMock()
    mock_store.path = None
    mock_store.save_scan.return_value = 1

    pipeline = Pipeline.__new__(Pipeline)
    pipeline._github = mock_github
    pipeline._llm = None
    pipeline._local_db = MagicMock()
    pipeline._local_db.fetch.return_value = {
        "owner_reputation": {
            "verdict": "CLEAN",
            "confidence": "certain",
            "matched_type": "owner",
            "score": 0.0,
            "note": None,
        }
    }
    pipeline._registry = mock_registry
    pipeline._scorer = mock_scorer
    pipeline._store = mock_store
    pipeline._silent = True

    pipeline.run("https://github.com/huggingface/testrepo", no_whitelist=True)
    assert captured[0]["whitelist_match"] is None
