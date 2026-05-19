"""Integration tests for Pipeline and feedback export.

GitHubFetcher is mocked — no real API calls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from legitifier_pkg.core.models import Verdict
from legitifier_pkg.feedback.export import export_jsonl
from legitifier_pkg.feedback.models import Confidence
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.pipeline import Pipeline

# ── Fixtures ──────────────────────────────────────────────────────────────────

now = datetime.now(UTC)


def _legit_data() -> dict:
    """Data profile of a healthy, legitimate repo."""
    return {
        "slug": "owner/legit-repo",
        "stars": 800,
        "forks": 120,
        "open_issues": 15,
        "watchers": 50,
        "created_at": now - timedelta(days=500),
        "pushed_at": now - timedelta(days=2),
        "owner_created_at": now - timedelta(days=1200),
        "owner_public_repos": 30,
        "owner_followers": 200,
        "readme": "A well-documented ML library. Benchmarks available. See paper.",
        "topics": ["machine-learning", "python"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 25,
        "stargazers_sample": [
            {
                "starred_at": now - timedelta(days=i * 3),
                "followers": 10,
                "public_repos": 15,
                "created_at": now - timedelta(days=300),
            }
            for i in range(50)
        ],
        "code_snippets": [
            {
                "path": "model.py",
                "content": "import torch\nmodel = AutoModel.from_pretrained('bert-base')",
            }
        ],
        "recent_prs": [
            {
                "title": "Add feature X",
                "created_at": now - timedelta(days=i * 5),
                "merged": True,
                "comments": 4,
                "user_followers": 20,
                "user_public_repos": 12,
                "user_created_at": now - timedelta(days=400),
            }
            for i in range(5)
        ],
        "commit_timeline": [
            {"month": f"2024-{i:02d}", "count": 8} for i in range(1, 13)
        ],
    }


def _scam_data() -> dict:
    """Data profile of a suspicious repo."""
    return {
        "slug": "fake/wormgpt-ultra",
        "stars": 8000,
        "forks": 20,
        "open_issues": 0,
        "watchers": 5,
        "created_at": now - timedelta(days=30),
        "pushed_at": now - timedelta(days=25),
        "owner_created_at": now - timedelta(days=35),
        "owner_public_repos": 1,
        "owner_followers": 0,
        "readme": "Run GPT-4 fully locally! No API key needed. 2GB RAM only. Join Telegram for uncensored version.",
        "topics": ["ai", "gpt"],
        "license": None,
        "default_branch": "main",
        "commit_count": 0,
        "stargazers_sample": [
            {
                "starred_at": now - timedelta(days=2),
                "followers": 0,
                "public_repos": 0,
                "created_at": now - timedelta(days=10),
            }
            for _ in range(80)
        ]
        + [
            {
                "starred_at": now - timedelta(days=20),
                "followers": 5,
                "public_repos": 8,
                "created_at": now - timedelta(days=300),
            }
            for _ in range(20)
        ],
        "code_snippets": [
            {
                "path": "main.py",
                "content": "from openai import OpenAI\nclient = OpenAI(api_key='sk-...')",
            }
        ],
        "recent_prs": [],
        "commit_timeline": [],
    }


# ── Pipeline tests ─────────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path):
    return FeedbackStore(db_path=tmp_path / "test.db")


def _make_pipeline(fetch_data: dict, store: FeedbackStore) -> Pipeline:
    pipeline = Pipeline(store=store, silent=True)
    pipeline._github = MagicMock()
    pipeline._github.fetch.return_value = fetch_data
    pipeline._llm = None
    return pipeline


class TestPipeline:
    def test_legit_repo_scores_low(self, store):
        pipeline = _make_pipeline(_legit_data(), store)
        report, scan_id = pipeline.run("github.com/owner/legit-repo")
        assert report.risk_score < 50
        assert report.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS)
        assert isinstance(scan_id, int)

    def test_scam_repo_scores_higher_than_legit(self, store):
        """Scam repo must score significantly higher than a legit repo."""
        pipeline_legit = _make_pipeline(_legit_data(), store)
        report_legit, _ = pipeline_legit.run("github.com/owner/legit-repo")

        pipeline_scam = _make_pipeline(_scam_data(), store)
        report_scam, _ = pipeline_scam.run("github.com/fake/wormgpt-ultra")

        assert report_scam.risk_score > report_legit.risk_score
        # At least 3 critical/high heuristics triggered
        triggered = [r for r in report_scam.results if r.triggered]
        assert len(triggered) >= 3

    def test_scan_saved_to_store(self, store):
        pipeline = _make_pipeline(_legit_data(), store)
        _, scan_id = pipeline.run("github.com/owner/legit-repo")
        records = store.export_annotated()
        assert len(records) == 0  # no feedback yet
        # add feedback and verify
        store.save_feedback(scan_id, Verdict.CLEAN, Confidence.CERTAIN)
        records = store.export_annotated()
        assert len(records) == 1

    def test_github_fetch_error_returns_empty_report(self, store):
        pipeline = Pipeline(store=store)
        pipeline._github = MagicMock()
        pipeline._github.fetch.side_effect = Exception("API down")
        pipeline._llm = None
        report, _ = pipeline.run("github.com/broken/repo")
        assert len(report.errors) > 0
        assert "GitHub fetch error" in report.errors[0]

    def test_all_heuristics_run(self, store):
        pipeline = _make_pipeline(_scam_data(), store)
        report, _ = pipeline.run("github.com/fake/wormgpt")
        heuristic_ids = {r.heuristic_id for r in report.results}
        expected = {
            "stars_velocity",
            "fork_ratio",
            "low_activity_stargazers",
            "ai_prs",
            "contributor_reputation",
            "watcher_to_star_ratio",
            "account_age",
            "commit_burst",
            "no_activity",
            "owner_reputation",
            "abandoned_takeover",
            "api_disguised_as_local",
            "hardcoded_secrets",
            "requirements_chaos",
            "test_coverage_signals",
            "documentation_quality",
            "readme_llm_analysis",
            "telegram_funnel",
        }
        assert expected == heuristic_ids

    def test_report_has_no_unknown_errors(self, store):
        pipeline = _make_pipeline(_legit_data(), store)
        report, _ = pipeline.run("github.com/owner/legit-repo")
        analyzer_errors = [e for e in report.errors if "Analyzer error" in e]
        assert analyzer_errors == []


# ── Export tests ───────────────────────────────────────────────────────────────


class TestExport:
    def test_export_empty(self, store, tmp_path):
        output = tmp_path / "out.jsonl"
        count = export_jsonl(output, store)
        assert count == 0
        assert output.read_text() == ""

    def test_export_with_feedback(self, store, tmp_path):
        from legitifier_pkg.core.models import ScanReport

        report = ScanReport(
            repo_url="https://github.com/x/y",
            risk_score=80.0,
            verdict=Verdict.SCAM,
            results=[],
        )
        scan_id = store.save_scan(report)
        store.save_feedback(scan_id, Verdict.SCAM, Confidence.CERTAIN, "obvious fake")

        output = tmp_path / "out.jsonl"
        count = export_jsonl(output, store)
        assert count == 1

        row = json.loads(output.read_text().strip())
        assert row["repo_url"] == "https://github.com/x/y"
        assert row["user_verdict"] == "SCAM"
        assert row["confidence"] == "certain"
        assert row["note"] == "obvious fake"
        assert "heuristic_scores" in row

    def test_export_multiple_records(self, store, tmp_path):
        from legitifier_pkg.core.models import ScanReport

        for i in range(3):
            report = ScanReport(
                repo_url=f"https://github.com/x/repo{i}",
                risk_score=60.0,
                verdict=Verdict.LIKELY_SCAM,
                results=[],
            )
            scan_id = store.save_scan(report)
            store.save_feedback(scan_id, Verdict.LIKELY_SCAM)

        output = tmp_path / "out.jsonl"
        count = export_jsonl(output, store)
        assert count == 3
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 3
