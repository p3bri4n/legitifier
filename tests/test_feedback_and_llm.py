import json
from unittest.mock import MagicMock

import pytest

from legitifier_pkg.analyzers.content import ContentAnalyzer
from legitifier_pkg.core.models import (
    HeuristicConfig,
    ScanReport,
    ScoringConfig,
    Verdict,
)
from legitifier_pkg.feedback.models import Confidence
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.fetchers.llm import LLMFetcher

# ── Feedback Store ────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path):
    return FeedbackStore(db_path=tmp_path / "test.db")


@pytest.fixture
def sample_report():
    return ScanReport(repo_url="https://github.com/x/y", risk_score=80.0,
                      verdict=Verdict.SCAM, results=[])


class TestFeedbackStore:
    def test_save_and_retrieve_scan(self, store, sample_report):
        scan_id = store.save_scan(sample_report)
        assert isinstance(scan_id, int)

    def test_save_feedback(self, store, sample_report):
        scan_id = store.save_scan(sample_report)
        record = store.save_feedback(scan_id, Verdict.SCAM, Confidence.CERTAIN, "obvious scam")
        assert record.user_verdict == Verdict.SCAM
        assert record.note == "obvious scam"

    def test_export_annotated(self, store, sample_report):
        scan_id = store.save_scan(sample_report)
        store.save_feedback(scan_id, Verdict.SCAM)
        records = store.export_annotated()
        assert len(records) == 1

    def test_unknown_scan_id_raises(self, store):
        with pytest.raises(KeyError):
            store.save_feedback(999, Verdict.SCAM)


# ── LLM Fetcher ───────────────────────────────────────────────────────────────

class TestLLMFetcher:
    def _fetcher(self, response: str) -> LLMFetcher:
        client = MagicMock()
        client.complete.return_value = response
        return LLMFetcher(client)

    def test_parses_valid_json(self):
        payload = json.dumps({"buzzword_density": 8, "claim_proof_ratio": 9,
                               "technical_coherence": 7, "red_flags": ["no weights"]})
        fetcher = self._fetcher(payload)
        result = fetcher.fetch({"readme": "test", "slug": "x/y", "stars": 100, "topics": []})
        assert result["llm_analysis"]["buzzword_density"] == 8

    def test_handles_json_in_markdown_fence(self):
        payload = f"```json\n{json.dumps({'buzzword_density': 5, 'claim_proof_ratio': 5, 'technical_coherence': 5, 'red_flags': []})}\n```"
        fetcher = self._fetcher(payload)
        result = fetcher.fetch({"readme": "", "slug": "", "stars": 0, "topics": []})
        assert result["llm_analysis"]["buzzword_density"] == 5

    def test_handles_invalid_json_gracefully(self):
        fetcher = self._fetcher("sorry I can't do that")
        result = fetcher.fetch({"readme": "", "slug": "", "stars": 0, "topics": []})
        assert result["llm_analysis"] == {}


# ── Content Analyzer ──────────────────────────────────────────────────────────

def _content_config() -> HeuristicConfig:
    return HeuristicConfig(
        id="readme_llm_analysis",
        category="content_claims",
        weight=1.0,
        severity="high",
        thresholds={"skip_if_missing": True},
        scoring=ScoringConfig(
            method="weighted_average",
            weights={"buzzword_density": 0.3, "claim_proof_ratio": 0.4, "technical_coherence": 0.3},
        ),
        evidence_template="Red flags: {red_flags} ({buzzword_density} {claim_proof_ratio} {technical_coherence})",
    )


class TestContentAnalyzer:
    def setup_method(self):
        self.analyzer = ContentAnalyzer()
        self.config = _content_config()

    def test_skips_gracefully_without_llm(self):
        result = self.analyzer.analyze(self.config, {})
        assert not result.triggered
        assert result.score == 0.0

    def test_high_scores_trigger(self):
        data = {"llm_analysis": {"buzzword_density": 9, "claim_proof_ratio": 10,
                                  "technical_coherence": 9, "red_flags": ["impossible claim"]}}
        result = self.analyzer.analyze(self.config, data)
        assert result.triggered
        assert result.score > 50

    def test_low_scores_clean(self):
        data = {"llm_analysis": {"buzzword_density": 1, "claim_proof_ratio": 1,
                                  "technical_coherence": 0, "red_flags": []}}
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered

    def test_red_flags_in_evidence(self):
        data = {"llm_analysis": {"buzzword_density": 9, "claim_proof_ratio": 10,
                                  "technical_coherence": 9, "red_flags": ["no weights", "Telegram upsell"]}}
        result = self.analyzer.analyze(self.config, data)
        assert "no weights" in result.evidence
