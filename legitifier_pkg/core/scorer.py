from __future__ import annotations

from legitifier_pkg.core.models import HeuristicResult, ScanReport, Severity

_WHITELIST_CAPS: dict[str, float | None] = {
    "certain": 49.0,
    "probable": 65.0,
    "unsure": None,  # no cap, just -10 bonus
}

_SEVERITY_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}

_BYPASS_CATEGORIES = {"code_quality", "content_claims"}


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
        whitelist_match: dict | None = None,
        duration: float = 0.0,
    ) -> ScanReport:
        if not results:
            risk_score = 0.0
        else:
            triggered = [r for r in results if r.triggered]

            if not triggered:
                risk_score = 0.0
            else:
                # Weighted average of triggered scores only
                total_weight = sum(self._weight(r) for r in triggered)
                weighted_avg = (
                    sum(r.score * self._weight(r) for r in triggered) / total_weight
                )

                # Boost from the single strongest signal
                max_score = max(r.score for r in triggered)
                boost = max_score * 0.25

                # Coverage: more heuristics triggered = more confident
                coverage = len(triggered) / len(results)
                coverage_factor = 0.5 + (coverage * 0.5)  # range [0.5, 1.0]

                risk_score = min((weighted_avg + boost) * coverage_factor, 100.0)

        risk_score = round(risk_score, 2)

        if whitelist_match and not self._should_bypass_whitelist(results):
            confidence = whitelist_match.get("confidence", "probable")
            cap = _WHITELIST_CAPS.get(confidence)
            if cap is not None:
                if risk_score > cap:
                    risk_score = cap
                    errors = [
                        *errors,
                        f"Score capped at {cap:.0f}: {whitelist_match.get('type', 'owner')}"
                        " is whitelisted (CLEAN, confidence="
                        f"{confidence}).",
                    ]
            else:
                # unsure: soft bonus only
                risk_score = max(risk_score - 10, 0)

        from legitifier_pkg import __version__

        return ScanReport(
            repo_url=repo_url,
            risk_score=risk_score,
            verdict=ScanReport.verdict_from_score(risk_score),
            results=results,
            errors=errors,
            scan_duration_seconds=duration,
            scanner_version=__version__,
        )

    @staticmethod
    def _should_bypass_whitelist(results: list[HeuristicResult]) -> bool:
        """Bypass whitelist cap when 2+ critical signals from code/content categories."""
        critical = [
            r for r in results if r.triggered and r.severity == Severity.CRITICAL
        ]
        if len(critical) < 2:
            return False
        return any(r.category in _BYPASS_CATEGORIES for r in critical)

    @staticmethod
    def _weight(result: HeuristicResult) -> float:
        return _SEVERITY_WEIGHT.get(result.severity.value, 1.0)
