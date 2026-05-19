from __future__ import annotations

from collections import Counter
from datetime import UTC, timedelta
from typing import Any

from legitifier_pkg.analyzers.base import BaseAnalyzer, analyzer_for
from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult


@analyzer_for("social_signals")
class SocialAnalyzer(BaseAnalyzer):
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        handler = getattr(self, f"_handle_{config.id}", self._handle_unknown)
        return handler(config, data)

    def _handle_stars_velocity(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        sample: list[dict] = data.get("stargazers_sample", [])
        t = config.thresholds
        window = t.get("spike_window_days", 3)
        spike_ratio = t.get("spike_ratio", 10)
        min_stars = t.get("min_stars_to_trigger", 500)

        stars = data.get("stars", 0)
        triggered = False
        spike_stars, avg_per_day = 0, 0.0
        context: dict[str, Any] = {
            "spike_stars": 0,
            "spike_days": window,
            "avg_stars_per_day": 0.0,
        }

        if stars >= min_stars and sample:
            counts = self._stars_per_day(sample)
            if counts and len(counts) > 1:
                max_window, spike_start = self._max_window_count(counts, window)

                # Baseline: days outside the spike window
                baseline = {
                    d: v
                    for d, v in counts.items()
                    if spike_start is None
                    or not (spike_start <= d < spike_start + timedelta(days=window))
                }

                if baseline:
                    # Average over the full observed period, not just days with stars
                    dates = sorted(counts)
                    total_days = max((dates[-1] - dates[0]).days, 1)
                    baseline_stars = sum(baseline.values())
                    baseline_days = max(total_days - window, 1)
                    avg_per_day = baseline_stars / baseline_days
                else:
                    avg_per_day = 0.0

                spike_per_day = max_window / window if window else 0
                if avg_per_day > 0 and spike_per_day >= avg_per_day * spike_ratio:
                    min_abs = t.get("min_spike_stars_absolute", 50)
                    if max_window >= min_abs:
                        triggered = True
                        spike_stars = max_window

            context = {
                "spike_stars": spike_stars,
                "spike_days": window,
                "avg_stars_per_day": round(avg_per_day, 1),
            }

        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=context,
        )

    def _handle_ai_prs(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        prs: list[dict] = data.get("recent_prs", [])
        if not prs:
            return self._clean_result(config)

        t = config.thresholds
        burst_window = t.get("burst_window_days", 7)
        min_burst = t.get("min_prs_in_burst", 5)
        max_followers = t.get("max_author_followers", 1)
        max_repos = t.get("max_author_repos", 3)
        min_dead_ratio = t.get("min_dead_pr_ratio", 0.85)
        min_suspicious_abs = t.get("min_suspicious_authors_absolute", 3)

        # Burst detection
        burst_count, _ = self._max_window_count(
            self._stars_per_day([{"starred_at": p["created_at"]} for p in prs]),
            burst_window,
        )

        # Dead PRs: not merged and no comments
        dead = sum(1 for p in prs if not p.get("merged") and p.get("comments", 0) == 0)
        dead_ratio = dead / len(prs)

        # Suspicious authors
        suspicious = sum(
            1
            for p in prs
            if p.get("user_followers", 0) <= max_followers
            and p.get("user_public_repos", 0) <= max_repos
        )
        suspicious_ratio = suspicious / len(prs)

        # Require both high ratio AND minimum absolute count to avoid FP on active repos
        triggered = (
            burst_count >= min_burst
            and dead_ratio >= min_dead_ratio
            and suspicious >= min_suspicious_abs
        )
        context = {
            "burst_count": burst_count,
            "burst_days": burst_window,
            "dead_ratio_pct": round(dead_ratio * 100),
            "suspicious_authors": round(suspicious_ratio * 100),
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=context,
        )

    def _handle_fork_ratio(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        stars = data.get("stars", 0)
        forks = data.get("forks", 0)
        created_at = data.get("created_at")
        t = config.thresholds
        min_stars = t.get("min_stars_to_trigger", 200)
        min_ratio = t.get("min_ratio", 0.03)
        min_age_days = t.get("min_repo_age_days", 365)

        # Skip young repos — low fork ratio is normal early in a project's life
        if created_at:
            from datetime import datetime

            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            age_days = (datetime.now(UTC) - created_at).days
            if age_days < min_age_days:
                return self._clean_result(config)

        triggered = False
        ratio = forks / stars if stars > 0 else 1.0
        context = {"ratio": round(ratio, 3), "forks": forks, "stars": stars}

        if stars >= min_stars and ratio < min_ratio:
            triggered = True

        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=context,
        )

    def _handle_low_activity_stargazers(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        sample: list[dict] = data.get("stargazers_sample", [])
        t = config.thresholds
        max_repos = t.get("max_public_repos", 2)
        max_followers = t.get("max_followers", 0)
        min_ratio_to_trigger = t.get("min_suspicious_ratio", 0.4)

        if not sample:
            return self._clean_result(config)

        suspicious = 0
        bought_profile = 0  # aged account + empty = likely purchased
        for u in sample:
            is_empty = (
                u.get("public_repos", 0) <= max_repos
                and u.get("followers", 0) <= max_followers
            )
            if is_empty:
                suspicious += 1
                # Bought profile pattern: account old (>365 days) but completely empty
                created_at = u.get("created_at")
                if created_at:
                    from datetime import datetime

                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=UTC)
                    age_days = (datetime.now(UTC) - created_at).days
                    if age_days > 365:
                        bought_profile += 1

        ratio = suspicious / len(sample)
        triggered = ratio >= min_ratio_to_trigger
        context = {
            "suspicious_count": suspicious,
            "sample_size": len(sample),
            "ratio_pct": round(ratio * 100, 1),
            "bought_profile_count": bought_profile,
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        # Boost score if many aged-but-empty accounts (stronger signal of purchase)
        if triggered and bought_profile > suspicious * 0.5:
            score = min(score + 10, 100.0)

        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=context,
        )

    def _handle_unknown(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        return self._clean_result(config)

    def _clean_result(self, config: HeuristicConfig) -> HeuristicResult:
        return HeuristicResult(
            heuristic_id=config.id,
            score=config.scoring.score_if_clean,
            triggered=False,
            evidence="No signal detected.",
            severity=config.severity,
        )

    @staticmethod
    def _stars_per_day(sample: list[dict]) -> Counter:
        counts: Counter = Counter()
        for item in sample:
            ts = item.get("starred_at")
            if ts:
                counts[ts.date()] += 1
        return counts

    @staticmethod
    def _max_window_count(counts: Counter, window_days: int) -> tuple[int, Any]:
        """Returns (max_count, start_date_of_spike)."""
        if not counts:
            return 0, None
        dates = sorted(counts)
        max_count, best_start = 0, None
        for start in dates:
            end = start + timedelta(days=window_days)
            total = sum(v for d, v in counts.items() if start <= d < end)
            if total > max_count:
                max_count, best_start = total, start
        return max_count, best_start

    def _handle_contributor_reputation(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        rep: dict = data.get("contributor_reputation") or {}
        score = float(rep.get("score", 0.0))
        min_score = config.thresholds.get("min_score_to_trigger", 30)
        triggered = score >= min_score
        flagged = rep.get("flagged_logins", [])
        context = {
            "flagged_count": len(flagged),
            "sample_size": rep.get("sample_size", 0),
            "flagged_logins": ", ".join(f["login"] for f in flagged) or "none",
        }
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=rep,
        )

    def _handle_watcher_to_star_ratio(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        stars = data.get("stars", 0)
        watchers = data.get("watchers", 0)
        t = config.thresholds
        min_stars = t.get("min_stars_to_trigger", 500)
        max_ratio = t.get("max_ratio", 0.002)
        max_stars_exempt = t.get("max_stars_exempt", 10000)

        if stars < min_stars:
            return self._clean_result(config)

        # Very large repos — GitHub watcher counts become unreliable
        if stars > max_stars_exempt:
            return self._clean_result(config)

        ratio = round(watchers / stars, 4) if stars > 0 else 1.0
        triggered = ratio < max_ratio
        context = {"ratio": ratio, "watchers": watchers, "stars": stars}

        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=context,
        )
