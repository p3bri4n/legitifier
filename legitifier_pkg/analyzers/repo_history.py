from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from legitifier_pkg.analyzers.base import BaseAnalyzer, analyzer_for
from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult


@analyzer_for("repo_history")
class RepoHistoryAnalyzer(BaseAnalyzer):
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        handler = getattr(self, f"_handle_{config.id}", self._handle_unknown)
        return handler(config, data)

    def _handle_abandoned_takeover(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        timeline: list[dict] = data.get("commit_timeline", [])
        created_at: datetime | None = data.get("created_at")

        if not timeline or not created_at:
            return self._clean_result(config)

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        t = config.thresholds
        min_dormant = t.get("min_dormant_months", 6)
        burst_window = t.get("burst_window_months", 2)
        min_burst_commits = t.get("min_burst_commits", 15)
        min_age_days = t.get("min_repo_age_days", 180)

        repo_age_days = (datetime.now(UTC) - created_at).days
        if repo_age_days < min_age_days:
            return self._clean_result(config)

        # Build month -> count map from timeline
        counts = {entry["month"]: entry["count"] for entry in timeline}
        months = sorted(counts)

        dormant_months, burst_commits, burst_months_found = (
            self._find_dormancy_then_burst(
                months, counts, min_dormant, burst_window, min_burst_commits
            )
        )

        triggered = dormant_months >= min_dormant and burst_commits >= min_burst_commits
        context = {
            "dormant_months": dormant_months,
            "burst_commits": burst_commits,
            "burst_months": burst_months_found,
            "repo_age_days": repo_age_days,
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        evidence = (
            self._render_evidence(config.evidence_template, context)
            if triggered
            else "No signal detected."
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=evidence,
            category=config.category,
            severity=config.severity,
            raw_data=context,
        )

    @staticmethod
    def _find_dormancy_then_burst(
        months: list[str],
        counts: dict[str, int],
        min_dormant: int,
        burst_window: int,
        min_burst: int,
    ) -> tuple[int, int, int]:
        """Find the longest dormancy followed by a burst. Returns (dormant_months, burst_commits, burst_window)."""
        best = (0, 0, 0)
        for i, month in enumerate(months):
            if counts.get(month, 0) > 0:
                continue
            # Count consecutive zero months
            dormant = 0
            j = i
            while j < len(months) and counts.get(months[j], 0) == 0:
                dormant += 1
                j += 1
            if dormant < min_dormant:
                continue
            # Count commits in burst_window months after dormancy
            burst = sum(
                counts.get(months[k], 0)
                for k in range(j, min(j + burst_window, len(months)))
            )
            if dormant > best[0] or (dormant == best[0] and burst > best[1]):
                best = (dormant, burst, burst_window)
        return best

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
            category=config.category,
            severity=config.severity,
        )
