from __future__ import annotations

from typing import Any

from legitifier_pkg.analyzers.base import BaseAnalyzer, analyzer_for
from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult


@analyzer_for("content_claims")
class ContentAnalyzer(BaseAnalyzer):
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        handler = getattr(self, f"_handle_{config.id}", self._handle_unknown)
        return handler(config, data)

    def _handle_readme_llm_analysis(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        llm: dict[str, Any] = data.get("llm_analysis") or {}

        if not llm and config.thresholds.get("skip_if_missing", True):
            return HeuristicResult(
                heuristic_id=config.id,
                score=0.0,
                triggered=False,
                evidence="LLM analysis skipped (no API key configured).",
                severity=config.severity,
            )

        buzzword = float(llm.get("buzzword_density", 0))
        claim_proof = float(llm.get("claim_proof_ratio", 0))
        coherence = float(llm.get("technical_coherence", 0))
        red_flags: list[str] = llm.get("red_flags", [])

        weights = config.scoring.weights
        w_total = sum(weights.values()) or 1.0
        raw_score = (
            buzzword * weights.get("buzzword_density", 0.3)
            + claim_proof * weights.get("claim_proof_ratio", 0.4)
            + coherence * weights.get("technical_coherence", 0.3)
        ) / w_total

        # LLM scores on 0-10, normalize to 0-100
        score = min(raw_score * 10, 100.0)
        triggered = score >= 50.0

        context = {
            "red_flags": "; ".join(red_flags) if red_flags else "none",
            "buzzword_density": buzzword,
            "claim_proof_ratio": claim_proof,
            "technical_coherence": coherence,
        }

        return HeuristicResult(
            heuristic_id=config.id,
            score=round(score, 2),
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={"llm": llm},
        )

    def _handle_unknown(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        return self._clean_result(config)

    def _clean_result(self, config: HeuristicConfig) -> HeuristicResult:
        return HeuristicResult(
            heuristic_id=config.id,
            score=config.scoring.score_if_clean,
            triggered=False,
            evidence="No signal detected.",
            severity=config.severity,
        )

    def _handle_telegram_funnel(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        readme: str = (data.get("readme") or "").lower()
        all_code = "\n".join(s["content"] for s in data.get("code_snippets", [])).lower()
        text = readme + "\n" + all_code

        t = config.thresholds
        telegram_patterns: list[str] = t.get("telegram_patterns", [])
        amplifier_patterns: list[str] = t.get("amplifier_patterns", [])

        telegram_matches = [p for p in telegram_patterns if p.lower() in text]
        amplifiers = [p for p in amplifier_patterns if p.lower() in text]

        triggered = bool(telegram_matches) and bool(amplifiers)
        # Telegram alone without commercial signals = likely community link, not scam
        score = config.scoring.score_if_triggered if triggered else config.scoring.score_if_clean

        context = {
            "telegram_matches": ", ".join(telegram_matches[:3]),
            "amplifier_note": f"Amplifiers: {', '.join(amplifiers[:3])}" if amplifiers else "",
        }
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={"telegram_matches": telegram_matches, "amplifiers": amplifiers},
        )
