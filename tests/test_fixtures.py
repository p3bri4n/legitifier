"""
Regression tests using realistic repo fixtures.
Each test verifies that a known pattern is correctly detected (or not).
These tests document the expected behavior and catch calibration regressions.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from legitifier_pkg.core.models import Verdict
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.pipeline import Pipeline
from tests.fixtures.repos import (
    abandoned_takeover_repo,
    api_wrapper_repo,
    bought_stars_repo,
    empty_readme_repo,
    legit_popular_repo,
    legit_small_repo,
    wormgpt_pattern_repo,
)


@pytest.fixture
def store(tmp_path):
    return FeedbackStore(db_path=tmp_path / "test.db")


def _pipeline(data: dict, store: FeedbackStore) -> Pipeline:
    p = Pipeline(store=store, silent=True)
    p._github = MagicMock()
    p._github.fetch.return_value = data
    p._llm = None
    return p


def _scan(data: dict, store: FeedbackStore):
    report, _ = _pipeline(data, store).run("github.com/owner/repo")
    return report


def _triggered_ids(report) -> set[str]:
    return {r.heuristic_id for r in report.results if r.triggered}


# ── Legitimate repos must score CLEAN ─────────────────────────────────────────


class TestLegitRepos:
    def test_popular_legit_is_clean(self, store):
        report = _scan(legit_popular_repo(), store)
        assert report.verdict == Verdict.CLEAN, (
            f"Got {report.verdict}, triggers: {_triggered_ids(report)}"
        )

    def test_small_legit_is_clean(self, store):
        report = _scan(legit_small_repo(), store)
        assert report.verdict == Verdict.CLEAN, (
            f"Got {report.verdict}, triggers: {_triggered_ids(report)}"
        )

    def test_legit_scores_lower_than_scam(self, store):
        legit = _scan(legit_popular_repo(), store)
        scam = _scan(bought_stars_repo(), store)
        assert legit.risk_score < scam.risk_score


# ── Scam patterns must trigger relevant heuristics ────────────────────────────


class TestBoughtStars:
    def test_triggers_low_fork_ratio(self, store):
        report = _scan(bought_stars_repo(), store)
        assert "fork_ratio" in _triggered_ids(report)

    def test_triggers_low_watcher_ratio(self, store):
        report = _scan(bought_stars_repo(), store)
        assert "watcher_to_star_ratio" in _triggered_ids(report)

    def test_triggers_low_activity_stargazers(self, store):
        report = _scan(bought_stars_repo(), store)
        assert "low_activity_stargazers" in _triggered_ids(report)

    def test_verdict_is_suspicious_or_worse(self, store):
        report = _scan(bought_stars_repo(), store)
        assert report.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_SCAM, Verdict.SCAM)


class TestApiWrapper:
    def test_triggers_api_disguised_as_local(self, store):
        report = _scan(api_wrapper_repo(), store)
        assert "api_disguised_as_local" in _triggered_ids(report)

    def test_triggers_no_activity(self, store):
        report = _scan(api_wrapper_repo(), store)
        assert "no_activity" in _triggered_ids(report)

    def test_verdict_is_suspicious_or_worse(self, store):
        report = _scan(api_wrapper_repo(), store)
        assert report.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_SCAM, Verdict.SCAM)


class TestEmptyReadmeRepo:
    def test_triggers_watcher_ratio(self, store):
        report = _scan(empty_readme_repo(), store)
        assert "watcher_to_star_ratio" in _triggered_ids(report)

    def test_triggers_fork_ratio(self, store):
        report = _scan(empty_readme_repo(), store)
        assert "fork_ratio" in _triggered_ids(report)

    def test_triggers_low_activity_stargazers(self, store):
        report = _scan(empty_readme_repo(), store)
        assert "low_activity_stargazers" in _triggered_ids(report)


class TestAbandonedTakeover:
    def test_triggers_abandoned_takeover(self, store):
        report = _scan(abandoned_takeover_repo(), store)
        assert "abandoned_takeover" in _triggered_ids(report)


class TestWormGPTPattern:
    def test_triggers_api_wrapper(self, store):
        report = _scan(wormgpt_pattern_repo(), store)
        assert "api_disguised_as_local" in _triggered_ids(report)

    def test_triggers_low_activity_stargazers(self, store):
        report = _scan(wormgpt_pattern_repo(), store)
        assert "low_activity_stargazers" in _triggered_ids(report)

    def test_verdict_is_suspicious_or_worse(self, store):
        report = _scan(wormgpt_pattern_repo(), store)
        assert report.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_SCAM, Verdict.SCAM)


# ── Score ordering sanity check ───────────────────────────────────────────────


class TestScoreOrdering:
    """Verify that more suspicious repos score higher than cleaner ones."""

    def test_wormgpt_scores_higher_than_legit(self, store):
        legit = _scan(legit_popular_repo(), store)
        worm = _scan(wormgpt_pattern_repo(), store)
        assert worm.risk_score > legit.risk_score

    def test_api_wrapper_scores_higher_than_legit(self, store):
        legit = _scan(legit_popular_repo(), store)
        wrapper = _scan(api_wrapper_repo(), store)
        assert wrapper.risk_score > legit.risk_score

    def test_bought_stars_scores_higher_than_legit(self, store):
        legit = _scan(legit_popular_repo(), store)
        bought = _scan(bought_stars_repo(), store)
        assert bought.risk_score > legit.risk_score


class TestWormGPTTelegramFunnel:
    def test_triggers_telegram_funnel(self, store):
        report = _scan(wormgpt_pattern_repo(), store)
        assert "telegram_funnel" in _triggered_ids(report)

    def test_telegram_funnel_not_triggered_on_legit(self, store):
        report = _scan(legit_popular_repo(), store)
        assert "telegram_funnel" not in _triggered_ids(report)


class TestHardcodedSecrets:
    def test_triggers_on_exposed_key(self, store):
        data = api_wrapper_repo()
        data["code_snippets"] = [
            {
                "path": "bot.py",
                "content": 'OPENAI_KEY = "sk-proj-abc123realkey"\nclient = openai.OpenAI()',
            }
        ]
        report = _scan(data, store)
        assert "hardcoded_secrets" in _triggered_ids(report)

    def test_not_triggered_on_placeholder(self, store):
        data = legit_popular_repo()
        data["code_snippets"] = [
            {
                "path": "config.py",
                "content": 'OPENAI_KEY = "YOUR_API_KEY"  # replace this',
            }
        ]
        report = _scan(data, store)
        assert "hardcoded_secrets" not in _triggered_ids(report)


class TestRequirementsChaos:
    def test_triggers_on_duplicate_packages(self, store):
        data = wormgpt_pattern_repo()
        data["code_snippets"] = [
            {
                "path": "requirements.txt",
                "content": "openai==0.28.0\nopenai==1.3.0\nnumpy\npandas",
            }
        ]
        report = _scan(data, store)
        assert "requirements_chaos" in _triggered_ids(report)

    def test_not_triggered_on_clean_requirements(self, store):
        data = legit_popular_repo()
        data["code_snippets"] = [
            {
                "path": "requirements.txt",
                "content": "requests==2.31.0\nnumpy==1.24.0\npandas==2.0.0",
            }
        ]
        report = _scan(data, store)
        assert "requirements_chaos" not in _triggered_ids(report)


class TestCoverageSignals:
    def test_triggers_on_no_tests(self, store):
        data = api_wrapper_repo()
        data["code_snippets"] = [
            {"path": "main.py", "content": "def run(): pass"},
            {"path": "utils.py", "content": "def helper(): pass"},
            {"path": "core.py", "content": "def process(): pass"},
            {"path": "app.py", "content": "def start(): pass"},
        ]
        report = _scan(data, store)
        assert "test_coverage_signals" in _triggered_ids(report)

    def test_triggers_on_empty_tests(self, store):
        data = wormgpt_pattern_repo()
        data["code_snippets"] = [
            {"path": "main.py", "content": "def run(): pass"},
            {"path": "test_main.py", "content": "def test_run():\n    assert True"},
        ]
        report = _scan(data, store)
        assert "test_coverage_signals" in _triggered_ids(report)

    def test_triggers_on_false_coverage_claim(self, store):
        data = empty_readme_repo()
        data["readme"] = (
            "# Project\n![coverage-100%](https://img.shields.io/badge/coverage-100%25-green)"
        )
        data["code_snippets"] = [
            {"path": "main.py", "content": "def run(): pass"},
            {"path": "utils.py", "content": "def helper(): pass"},
            {"path": "core.py", "content": "def process(): pass"},
            {"path": "app.py", "content": "def start(): pass"},
            # no test files — badge claims 100% but no tests found
        ]
        report = _scan(data, store)
        # Should trigger: source files found, badge claimed, no tests
        assert "test_coverage_signals" in _triggered_ids(report)

    def test_not_triggered_on_legit_with_tests(self, store):
        data = legit_popular_repo()
        data["code_snippets"] = [
            {"path": "model.py", "content": "class Model: pass"},
            {"path": "utils.py", "content": "def helper(): pass"},
            {
                "path": "tests/test_model.py",
                "content": "def test_model():\n    m = Model()\n    assert m is not None",
            },
            {
                "path": "tests/test_utils.py",
                "content": "def test_helper():\n    assert helper() == expected",
            },
        ]
        report = _scan(data, store)
        assert "test_coverage_signals" not in _triggered_ids(report)


class TestDocumentationQuality:
    def test_triggers_on_empty_readme_and_no_comments(self, store):
        data = wormgpt_pattern_repo()
        data["readme"] = "# Tool\nDoes stuff."  # very short
        data["code_snippets"] = [
            {"path": "main.py", "content": "def run():\n    x = 1\n    return x"},
            {"path": "utils.py", "content": "def helper():\n    return True"},
            {"path": "core.py", "content": "def process(data):\n    return data"},
            {"path": "app.py", "content": "def start():\n    run()"},
        ]
        report = _scan(data, store)
        assert "documentation_quality" in _triggered_ids(report)

    def test_not_triggered_on_legit(self, store):
        data = legit_popular_repo()
        # legit_popular_repo has a proper readme and we add commented code
        data["code_snippets"] = [
            {
                "path": "model.py",
                "content": '# Main model class\n\ndef train():\n    """Train the model."""\n    pass',
            },
            {
                "path": "utils.py",
                "content": "# Utility functions\n\ndef preprocess(data):\n    # Clean input\n    return data",
            },
        ]
        report = _scan(data, store)
        assert "documentation_quality" not in _triggered_ids(report)
