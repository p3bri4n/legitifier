from datetime import UTC, datetime, timedelta

from legitifier_pkg.analyzers.social import SocialAnalyzer
from legitifier_pkg.core.models import HeuristicConfig, ScoringConfig


def _config(heuristic_id: str, thresholds: dict) -> HeuristicConfig:
    return HeuristicConfig(
        id=heuristic_id,
        category="social_signals",
        weight=1.0,
        severity="high",
        thresholds=thresholds,
        scoring=ScoringConfig(score_if_triggered=75, score_if_clean=0),
        evidence_template="evidence",
    )


def _make_sample(
    n: int, days_ago: int = 0, followers: int = 0, repos: int = 0
) -> list[dict]:
    base = datetime.now(UTC) - timedelta(days=days_ago)
    return [
        {
            "login": f"u{i}",
            "starred_at": base,
            "followers": followers,
            "public_repos": repos,
            "created_at": base,
        }
        for i in range(n)
    ]


class TestSocialAnalyzer:
    def setup_method(self):
        self.analyzer = SocialAnalyzer()

    def test_fork_ratio_triggered(self):
        config = _config("fork_ratio", {"min_stars_to_trigger": 100, "min_ratio": 0.02})
        data = {"stars": 10000, "forks": 10}
        result = self.analyzer.analyze(config, data)
        assert result.triggered
        assert result.score == 75

    def test_fork_ratio_clean(self):
        config = _config("fork_ratio", {"min_stars_to_trigger": 100, "min_ratio": 0.02})
        data = {"stars": 1000, "forks": 100}
        result = self.analyzer.analyze(config, data)
        assert not result.triggered

    def test_low_activity_stargazers_triggered(self):
        config = _config(
            "low_activity_stargazers",
            {"max_public_repos": 2, "max_followers": 0, "min_suspicious_ratio": 0.4},
        )
        data = {"stargazers_sample": _make_sample(10, followers=0, repos=0)}
        result = self.analyzer.analyze(config, data)
        assert result.triggered

    def test_low_activity_stargazers_clean(self):
        config = _config(
            "low_activity_stargazers",
            {"max_public_repos": 2, "max_followers": 0, "min_suspicious_ratio": 0.4},
        )
        data = {"stargazers_sample": _make_sample(10, followers=50, repos=20)}
        result = self.analyzer.analyze(config, data)
        assert not result.triggered

    def test_unknown_heuristic_returns_clean(self):
        config = _config("nonexistent_heuristic", {})
        result = self.analyzer.analyze(config, {})
        assert not result.triggered
        assert result.score == 0


class TestStarsVelocity:
    def setup_method(self):
        self.analyzer = SocialAnalyzer()
        self.config = HeuristicConfig(
            id="stars_velocity",
            category="social_signals",
            weight=1.0,
            severity="high",
            thresholds={
                "spike_ratio": 10,
                "spike_window_days": 3,
                "min_stars_to_trigger": 500,
            },
            scoring=ScoringConfig(score_if_triggered=75, score_if_clean=0),
            evidence_template="{spike_stars} {spike_days} {avg_stars_per_day}",
        )

    def _sample(self, counts_by_days_ago: list[tuple[int, int]]) -> list[dict]:
        """Build stargazer sample: list of (days_ago, count) tuples."""
        now = datetime.now()
        sample = []
        for days_ago, count in counts_by_days_ago:
            ts = now - timedelta(days=days_ago)
            for _ in range(count):
                sample.append(
                    {
                        "starred_at": ts,
                        "followers": 5,
                        "public_repos": 10,
                        "created_at": ts,
                    }
                )
        return sample

    def test_triggered_spike(self):
        # 1/day average, then 50 in 1 day → spike_ratio >> 10
        sample = self._sample([(i, 1) for i in range(20, 5, -1)] + [(2, 50)])
        data = {"stars": 1000, "stargazers_sample": sample}
        result = self.analyzer.analyze(self.config, data)
        assert result.triggered
        assert result.score == 75

    def test_clean_steady_growth(self):
        # ~5/day steady — no spike
        sample = self._sample([(i, 5) for i in range(20, 0, -1)])
        data = {"stars": 1000, "stargazers_sample": sample}
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered

    def test_clean_below_min_stars(self):
        # Spike but not enough total stars
        sample = self._sample([(2, 50)])
        data = {"stars": 100, "stargazers_sample": sample}
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered

    def test_clean_empty_sample(self):
        data = {"stars": 1000, "stargazers_sample": []}
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered
        assert result.score == 0

    def test_clean_sample_without_timestamps(self):
        # starred_at is None — should not crash
        data = {"stars": 1000, "stargazers_sample": [{"starred_at": None}] * 10}
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered
