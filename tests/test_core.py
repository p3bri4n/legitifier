from pathlib import Path

import pytest

from legitifier_pkg.core.models import HeuristicResult, Severity, Verdict
from legitifier_pkg.core.registry import HeuristicRegistry
from legitifier_pkg.core.scorer import Scorer

HEURISTICS_ROOT = Path(__file__).parents[1] / "heuristics"


class TestRegistry:
    def test_loads_all_yaml(self):
        registry = HeuristicRegistry(HEURISTICS_ROOT)
        registry.load()
        assert len(registry.all()) > 0

    def test_by_category(self):
        registry = HeuristicRegistry(HEURISTICS_ROOT)
        registry.load()
        social = registry.by_category("social_signals")
        assert all(h.category == "social_signals" for h in social)

    def test_duplicate_id_raises(self, tmp_path):
        (tmp_path / "a.yaml").write_text("id: dup\ncategory: x\nweight: 1.0\n")
        (tmp_path / "b.yaml").write_text("id: dup\ncategory: x\nweight: 1.0\n")
        registry = HeuristicRegistry(tmp_path)
        with pytest.raises(ValueError, match="Duplicate"):
            registry.load()


class TestScorer:
    def _result(self, score: float, severity: str = "medium") -> HeuristicResult:
        return HeuristicResult(
            heuristic_id="test",
            score=score,
            triggered=score > 0,
            evidence="test",
            severity=Severity(severity),
        )

    def test_clean_verdict(self):
        scorer = Scorer()
        report = scorer.aggregate("https://github.com/x/y", [self._result(0)], [])
        assert report.verdict == Verdict.CLEAN

    def test_scam_verdict(self):
        scorer = Scorer()
        report = scorer.aggregate(
            "https://github.com/x/y", [self._result(90, "critical")], []
        )
        assert report.verdict == Verdict.SCAM

    def test_empty_results(self):
        scorer = Scorer()
        report = scorer.aggregate("https://github.com/x/y", [], [])
        assert report.risk_score == 0.0

    def test_whitelist_caps_score(self):
        scorer = Scorer()
        report = scorer.aggregate(
            "url",
            [self._result(90, "critical")],
            [],
            whitelist_match={"confidence": "certain", "type": "owner"},
        )
        assert report.risk_score == 49.0
        assert report.verdict == Verdict.SUSPICIOUS
        assert any("capped" in e for e in report.errors)

    def test_whitelist_no_effect_on_low_score(self):
        scorer = Scorer()
        report = scorer.aggregate(
            "url",
            [self._result(10)],
            [],
            whitelist_match={"confidence": "certain", "type": "owner"},
        )
        assert report.risk_score < 49.0
        assert report.verdict == Verdict.CLEAN
        scorer = Scorer()
        # critical result should weigh more than low
        r_critical = self._result(50, "critical")
        r_low = self._result(0, "low")
        report = scorer.aggregate("url", [r_critical, r_low], [])
        assert report.risk_score > 25  # pulled toward 50 by critical weight
