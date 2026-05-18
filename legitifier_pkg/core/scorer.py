from __future__ import annotations

from legitifier_pkg.core.models import HeuristicResult, ScanReport

_WHITELIST_MAX_SCORE = 49.0

_SEVERITY_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}


class Scorer:
    """
    Hybrid scoring strategy:

    1. Weighted average of triggered heuristics only (not diluted by 0s)
    2. Boosted by the highest single severity signal
    3. Scaled by trigger coverage (how many heuristics fired)

    Formula:
        base  = weighted_avg(triggered scores)
        boost = max_single_score * 0.2          # amplify strongest signal
        coverage_factor = triggered / total      # penalize sparse signals
        final = (base + boost) * coverage_factor

    This means:
    - 1 critical signal alone → moderate score (not buried by 10 zeros)
    - Multiple signals → high score
    - All clear → 0
    """

    def aggregate(
        self,
        repo_url: str,
        results: list[HeuristicResult],
        errors: list[str],
        whitelisted: bool = False,
        duration: float = 0.0,
    ) -> ScanReport:
        if not results:
            final_score = 0.0
        else:
            triggered = [r for r in results if r.triggered]

            if not triggered:
                final_score = 0.0
            else:
                # Weighted average of triggered scores only
                total_weight = sum(self._weight(r) for r in triggered)
                weighted_avg = sum(r.score * self._weight(r) for r in triggered) / total_weight

                # Boost from the single strongest signal
                max_score = max(r.score for r in triggered)
                boost = max_score * 0.25

                # Coverage: more heuristics triggered = more confident
                coverage = len(triggered) / len(results)
                coverage_factor = 0.5 + (coverage * 0.5)  # range [0.5, 1.0]

                final_score = min((weighted_avg + boost) * coverage_factor, 100.0)

        final_score = round(final_score, 2)

        if whitelisted and final_score > _WHITELIST_MAX_SCORE:
            final_score = _WHITELIST_MAX_SCORE
            errors = [*errors, "Score capped: owner/repo is whitelisted (CLEAN in reputation store)."]

        return ScanReport(
            repo_url=repo_url,
            final_score=final_score,
            verdict=ScanReport.verdict_from_score(final_score),
            results=results,
            errors=errors,
            scan_duration_seconds=duration,
        )

    @staticmethod
    def _weight(result: HeuristicResult) -> float:
        return _SEVERITY_WEIGHT.get(result.severity.value, 1.0)
