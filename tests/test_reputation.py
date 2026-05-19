import json
from pathlib import Path

import pytest

from legitifier_pkg.data.loader import ReputationStore
from legitifier_pkg.data.models import (
    ReputationVerdict,
)
from legitifier_pkg.fetchers.local_db import LocalDBFetcher


@pytest.fixture
def seed_file(tmp_path) -> Path:
    path = tmp_path / "seed.jsonl"
    entries = [
        {
            "type": "owner",
            "login": "evil-org",
            "verdict": "SCAM",
            "confidence": "certain",
            "source": "manual",
            "note": "known scammer",
            "added": "2026-05-16",
        },
        {
            "type": "repo",
            "slug": "evil-org/wormgpt",
            "verdict": "SCAM",
            "confidence": "certain",
            "source": "manual",
            "note": "API wrapper scam",
            "added": "2026-05-16",
        },
        {
            "type": "owner",
            "login": "maybe-bad",
            "verdict": "SUSPICIOUS",
            "confidence": "probable",
            "source": "manual",
            "note": "pattern matches",
            "added": "2026-05-16",
        },
        {
            "type": "owner",
            "login": "legit-dev",
            "verdict": "CLEAN",
            "confidence": "certain",
            "source": "manual",
            "note": "verified researcher",
            "added": "2026-05-16",
        },
    ]
    path.write_text("\n".join(json.dumps(e) for e in entries))
    return path


class TestReputationStore:
    def test_loads_seed(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        assert store.lookup("evil-org") is not None

    def test_lookup_by_slug(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        entry = store.lookup("evil-org/wormgpt")
        assert entry is not None
        assert entry.verdict == ReputationVerdict.SCAM

    def test_lookup_unknown_returns_none(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        assert store.lookup("unknown-dev") is None

    def test_score_scam_certain(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        score = store.score("evil-org")
        assert score == 90.0  # 90 * 1.0 (certain)

    def test_score_suspicious_probable(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        score = store.score("maybe-bad")
        assert score == 30.0  # 50 * 0.6 (probable)

    def test_score_clean_returns_zero(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        assert store.score("legit-dev") == 0.0

    def test_score_unknown_returns_zero(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        assert store.score("nobody") == 0.0

    def test_ignores_comments_and_blank_lines(self, tmp_path):
        path = tmp_path / "seed.jsonl"
        path.write_text("# comment\n\n")
        store = ReputationStore(seed_path=path)
        assert list(store.all_keys()) == []

    def test_missing_seed_file_doesnt_crash(self, tmp_path):
        store = ReputationStore(seed_path=tmp_path / "nonexistent.jsonl")
        assert store.lookup("anything") is None


class TestLocalDBFetcher:
    def test_clean_owner_returns_zero_score(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        result = fetcher.fetch({"slug": "legit-dev/cool-project", "recent_prs": []})
        assert result["owner_reputation"]["score"] == 0.0

    def test_known_scam_owner_returns_high_score(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        result = fetcher.fetch({"slug": "evil-org/some-repo", "recent_prs": []})
        assert result["owner_reputation"]["score"] == 90.0
        assert result["owner_reputation"]["verdict"] == "SCAM"

    def test_known_scam_repo_slug_takes_priority(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        result = fetcher.fetch({"slug": "evil-org/wormgpt", "recent_prs": []})
        assert result["owner_reputation"]["score"] == 90.0

    def test_contributor_reputation_flagged(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        prs = [
            {
                "user_login": "evil-org",
                "title": "Add feature",
                "created_at": None,
                "merged": False,
                "comments": 0,
                "user_followers": 0,
                "user_public_repos": 1,
            },
            {
                "user_login": "normal-dev",
                "title": "Fix bug",
                "created_at": None,
                "merged": True,
                "comments": 3,
                "user_followers": 10,
                "user_public_repos": 20,
            },
        ]
        result = fetcher.fetch({"slug": "victim/repo", "recent_prs": prs})
        rep = result["contributor_reputation"]
        assert rep["score"] > 0
        assert any(f["login"] == "evil-org" for f in rep["flagged_logins"])

    def test_contributor_reputation_clean(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        prs = [
            {
                "user_login": "legit-dev",
                "title": "Fix",
                "created_at": None,
                "merged": True,
                "comments": 2,
                "user_followers": 50,
                "user_public_repos": 30,
            }
        ]
        result = fetcher.fetch({"slug": "owner/repo", "recent_prs": prs})
        assert result["contributor_reputation"]["score"] == 0.0

    def test_no_prs_returns_zero(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        result = fetcher.fetch({"slug": "owner/repo", "recent_prs": []})
        assert result["contributor_reputation"]["score"] == 0.0


class TestContributorReputationPropagation:
    def _make_store(self, tmp_path):
        from legitifier_pkg.feedback.store import FeedbackStore

        return FeedbackStore(db_path=tmp_path / "scans.db")

    def _make_report(self, risk_score: float, flagged_logins: list[str]):
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

    def test_records_flagged_contributors_on_scam(self, tmp_path):
        store = self._make_store(tmp_path)
        report = self._make_report(
            risk_score=80.0, flagged_logins=["bad_actor1", "bad_actor2"]
        )
        count = store.record_contributor_reputation(report)
        # 2 flagged contributors + 1 owner (risk_score >= 75)
        assert count >= 2

    def test_no_recording_on_clean_repo(self, tmp_path):
        store = self._make_store(tmp_path)
        report = self._make_report(risk_score=10.0, flagged_logins=["some_user"])
        count = store.record_contributor_reputation(report)
        assert count == 0

    def test_no_duplicate_recording(self, tmp_path):
        store = self._make_store(tmp_path)
        report = self._make_report(risk_score=80.0, flagged_logins=["bad_actor"])
        first = store.record_contributor_reputation(report)
        second = store.record_contributor_reputation(report)
        assert first > 0
        assert second == 0  # already exists

    def test_recorded_contributor_found_by_lookup(self, tmp_path):
        from legitifier_pkg.data.loader import ReputationStore

        store = self._make_store(tmp_path)
        report = self._make_report(risk_score=60.0, flagged_logins=["bad_actor"])
        count = store.record_contributor_reputation(report)
        assert count > 0

        # Instantiate AFTER insertion so entries are loaded from DB
        rep_store = ReputationStore(
            seed_path=tmp_path / "empty.jsonl", db_path=store.path
        )
        entry = rep_store.lookup("bad_actor")
        assert entry is not None
        assert entry.verdict.value in ("SUSPICIOUS", "SCAM")
