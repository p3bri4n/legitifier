from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from legitifier_pkg.analyzers.base import BaseAnalyzer, analyzer_for
from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult


@analyzer_for("repo_metadata")
class MetadataAnalyzer(BaseAnalyzer):
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        handler = getattr(self, f"_handle_{config.id}", self._handle_unknown)
        return handler(config, data)

    def _handle_account_age(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        created_at: datetime | None = data.get("owner_created_at")
        if created_at is None:
            return self._clean_result(config)

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        age_days = (datetime.now(UTC) - created_at).days
        min_days = config.thresholds.get("min_account_age_days", 90)
        triggered = age_days < min_days
        context = {"age_days": age_days, "min_days": min_days}

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

    def _handle_commit_burst(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        created_at: datetime | None = data.get("created_at")
        pushed_at: datetime | None = data.get("pushed_at")
        commit_count: int = data.get("commit_count", 0)

        if not created_at or not pushed_at:
            return self._clean_result(config)

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        if pushed_at.tzinfo is None:
            pushed_at = pushed_at.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        repo_age_days = max((now - created_at).days, 1)
        active_days = max((pushed_at - created_at).days, 1)  # how long commits happened
        days_since_push = (now - pushed_at).days

        min_dormant = config.thresholds.get("min_dormant_days", 60)
        max_active_days = config.thresholds.get("max_repo_age_days", 14)
        min_commits = config.thresholds.get("min_commits", 5)

        # Pattern: all activity in first N days, then long silence
        triggered = (
            active_days <= max_active_days
            and days_since_push >= min_dormant
            and repo_age_days >= min_dormant  # repo old enough to be "abandoned"
            and commit_count >= min_commits
        )
        context = {
            "commit_count": commit_count,
            "repo_age_days": repo_age_days,
            "days_since_push": days_since_push,
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

    def _handle_no_activity(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        stars = data.get("stars", 0)
        open_issues = data.get("open_issues", 0)
        commit_count = data.get("commit_count", 0)
        min_stars = config.thresholds.get("min_stars_to_trigger", 500)

        # stars=0 likely means fetch failed — don't trigger on empty data
        if stars == 0:
            return self._clean_result(config)

        # Repo pushed recently -> consider active regardless of commit sample window
        pushed_at: datetime | None = data.get("pushed_at")
        if pushed_at:
            if pushed_at.tzinfo is None:
                pushed_at = pushed_at.replace(tzinfo=UTC)
            if (datetime.now(UTC) - pushed_at).days < 30:
                return self._clean_result(config)

        triggered = stars >= min_stars and open_issues == 0 and commit_count == 0
        context = {
            "stars": stars,
            "open_issues": open_issues,
            "commit_count": commit_count,
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

    def _handle_owner_reputation(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        rep: dict = data.get("owner_reputation") or {}
        score = float(rep.get("score", 0.0))
        min_score = config.thresholds.get("min_score_to_trigger", 40)
        triggered = score >= min_score

        if not rep.get("verdict"):
            return HeuristicResult(
                heuristic_id=config.id,
                score=0.0,
                triggered=False,
                evidence="Not in reputation database.",
                severity=config.severity,
                raw_data=rep,
            )

        context = {
            "verdict": rep.get("verdict"),
            "confidence": rep.get("confidence"),
            "note": rep.get("note") or "no details",
        }
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data=rep,
        )
