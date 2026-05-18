from datetime import UTC, datetime, timedelta

from legitifier_pkg.analyzers.metadata import MetadataAnalyzer
from legitifier_pkg.core.models import HeuristicConfig, ScoringConfig


def _config(heuristic_id: str, thresholds: dict) -> HeuristicConfig:
    return HeuristicConfig(
        id=heuristic_id,
        category="repo_metadata",
        weight=1.0,
        severity="high",
        thresholds=thresholds,
        scoring=ScoringConfig(score_if_triggered=65, score_if_clean=0),
        evidence_template="{age_days} {min_days} {commit_count} {repo_age_days} {days_since_push} {stars} {open_issues}",
    )


now = datetime.now(UTC)


class TestMetadataAnalyzer:
    def setup_method(self):
        self.analyzer = MetadataAnalyzer()

    def test_account_age_triggered(self):
        config = _config("account_age", {"min_account_age_days": 90})
        data = {"owner_created_at": now - timedelta(days=10)}
        result = self.analyzer.analyze(config, data)
        assert result.triggered

    def test_account_age_clean(self):
        config = _config("account_age", {"min_account_age_days": 90})
        data = {"owner_created_at": now - timedelta(days=200)}
        result = self.analyzer.analyze(config, data)
        assert not result.triggered

    def test_account_age_missing_data(self):
        config = _config("account_age", {"min_account_age_days": 90})
        result = self.analyzer.analyze(config, {})
        assert not result.triggered

    def test_commit_burst_triggered(self):
        config = _config("commit_burst", {"max_repo_age_days": 14, "min_commits": 5, "min_dormant_days": 60})
        data = {
            "created_at": now - timedelta(days=80),
            "pushed_at": now - timedelta(days=70),  # dormant 70 days
            "commit_count": 10,
        }
        result = self.analyzer.analyze(config, data)
        assert result.triggered

    def test_commit_burst_clean_recent_push(self):
        config = _config("commit_burst", {"max_repo_age_days": 14, "min_commits": 5, "min_dormant_days": 60})
        data = {
            "created_at": now - timedelta(days=10),
            "pushed_at": now - timedelta(days=1),  # active
            "commit_count": 10,
        }
        result = self.analyzer.analyze(config, data)
        assert not result.triggered

    def test_no_activity_triggered(self):
        config = _config("no_activity", {"min_stars_to_trigger": 500})
        data = {"stars": 5000, "open_issues": 0, "commit_count": 0}
        result = self.analyzer.analyze(config, data)
        assert result.triggered

    def test_no_activity_clean(self):
        config = _config("no_activity", {"min_stars_to_trigger": 500})
        data = {"stars": 5000, "open_issues": 12, "commit_count": 5}
        result = self.analyzer.analyze(config, data)
        assert not result.triggered

    def test_unknown_heuristic_returns_clean(self):
        config = _config("nonexistent", {})
        result = self.analyzer.analyze(config, {})
        assert not result.triggered
