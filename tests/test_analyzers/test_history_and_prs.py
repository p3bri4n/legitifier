from datetime import UTC, datetime, timedelta

from legitifier_pkg.analyzers.repo_history import RepoHistoryAnalyzer
from legitifier_pkg.analyzers.social import SocialAnalyzer
from legitifier_pkg.core.models import HeuristicConfig, ScoringConfig

now = datetime.now(UTC)


def _config(heuristic_id: str, category: str, thresholds: dict) -> HeuristicConfig:
    return HeuristicConfig(
        id=heuristic_id,
        category=category,
        weight=1.0,
        severity="high",
        thresholds=thresholds,
        scoring=ScoringConfig(score_if_triggered=75, score_if_clean=0),
        evidence_template="{burst_count} {burst_days} {dead_ratio_pct} {suspicious_authors} "
                          "{dormant_months} {burst_commits} {burst_months} {repo_age_days}",
    )


def _pr(merged: bool = False, comments: int = 0, days_ago: int = 0,
        followers: int = 0, repos: int = 1) -> dict:
    return {
        "title": "fix: update",
        "created_at": now - timedelta(days=days_ago),
        "merged": merged,
        "comments": comments,
        "user_followers": followers,
        "user_public_repos": repos,
        "user_created_at": now - timedelta(days=30),
    }


def _timeline(pattern: list[tuple[str, int]]) -> list[dict]:
    return [{"month": m, "count": c} for m, c in pattern]


class TestAIPRs:
    def setup_method(self):
        self.analyzer = SocialAnalyzer()
        self.config = _config("ai_prs", "social_signals", {
            "burst_window_days": 7, "min_prs_in_burst": 5,
            "max_author_followers": 1, "max_author_repos": 3,
            "min_dead_pr_ratio": 0.7,
        })

    def test_triggered_burst_dead_prs(self):
        prs = [_pr(merged=False, comments=0, days_ago=i) for i in range(8)]
        result = self.analyzer.analyze(self.config, {"recent_prs": prs})
        assert result.triggered

    def test_clean_merged_prs(self):
        prs = [_pr(merged=True, comments=3, days_ago=i * 10) for i in range(8)]
        result = self.analyzer.analyze(self.config, {"recent_prs": prs})
        assert not result.triggered

    def test_clean_no_prs(self):
        result = self.analyzer.analyze(self.config, {"recent_prs": []})
        assert not result.triggered

    def test_clean_burst_but_comments(self):
        # Burst but PRs have comments — real community
        prs = [_pr(merged=False, comments=5, days_ago=i) for i in range(8)]
        result = self.analyzer.analyze(self.config, {"recent_prs": prs})
        assert not result.triggered


class TestAbandonedTakeover:
    def setup_method(self):
        self.analyzer = RepoHistoryAnalyzer()
        self.config = _config("abandoned_takeover", "repo_history", {
            "min_dormant_months": 6, "burst_window_months": 2,
            "min_burst_commits": 15, "min_repo_age_days": 180,
        })

    def _data(self, timeline, age_days=400):
        return {
            "commit_timeline": timeline,
            "created_at": now - timedelta(days=age_days),
            "pushed_at": now,
        }

    def test_triggered_dormancy_then_burst(self):
        timeline = _timeline([
            ("2023-01", 10), ("2023-02", 8),
            # 7 months dormant
            ("2023-09", 0), ("2023-10", 0), ("2023-11", 0),
            ("2023-12", 0), ("2024-01", 0), ("2024-02", 0), ("2024-03", 0),
            # burst
            ("2024-04", 20), ("2024-05", 18),
        ])
        result = self.analyzer.analyze(self.config, self._data(timeline))
        assert result.triggered

    def test_clean_steady_activity(self):
        timeline = _timeline([(f"2024-{i:02d}", 5) for i in range(1, 13)])
        result = self.analyzer.analyze(self.config, self._data(timeline))
        assert not result.triggered

    def test_clean_too_young(self):
        timeline = _timeline([("2024-01", 0)] * 6 + [("2024-07", 20)])
        result = self.analyzer.analyze(self.config, self._data(timeline, age_days=90))
        assert not result.triggered

    def test_clean_no_timeline(self):
        result = self.analyzer.analyze(self.config, {"commit_timeline": [], "created_at": now - timedelta(days=400)})
        assert not result.triggered
