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
        {"type": "owner", "login": "evil-org", "verdict": "SCAM",
         "confidence": "certain", "source": "manual", "note": "known scammer", "added": "2026-05-16"},
        {"type": "repo", "slug": "evil-org/wormgpt", "verdict": "SCAM",
         "confidence": "certain", "source": "manual", "note": "API wrapper scam", "added": "2026-05-16"},
        {"type": "owner", "login": "maybe-bad", "verdict": "SUSPICIOUS",
         "confidence": "probable", "source": "manual", "note": "pattern matches", "added": "2026-05-16"},
        {"type": "owner", "login": "legit-dev", "verdict": "CLEAN",
         "confidence": "certain", "source": "manual", "note": "verified researcher", "added": "2026-05-16"},
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
            {"user_login": "evil-org", "title": "Add feature", "created_at": None,
             "merged": False, "comments": 0, "user_followers": 0, "user_public_repos": 1},
            {"user_login": "normal-dev", "title": "Fix bug", "created_at": None,
             "merged": True, "comments": 3, "user_followers": 10, "user_public_repos": 20},
        ]
        result = fetcher.fetch({"slug": "victim/repo", "recent_prs": prs})
        rep = result["contributor_reputation"]
        assert rep["score"] > 0
        assert any(f["login"] == "evil-org" for f in rep["flagged_logins"])

    def test_contributor_reputation_clean(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        prs = [{"user_login": "legit-dev", "title": "Fix", "created_at": None,
                "merged": True, "comments": 2, "user_followers": 50, "user_public_repos": 30}]
        result = fetcher.fetch({"slug": "owner/repo", "recent_prs": prs})
        assert result["contributor_reputation"]["score"] == 0.0

    def test_no_prs_returns_zero(self, seed_file):
        store = ReputationStore(seed_path=seed_file)
        fetcher = LocalDBFetcher(store=store)
        result = fetcher.fetch({"slug": "owner/repo", "recent_prs": []})
        assert result["contributor_reputation"]["score"] == 0.0
