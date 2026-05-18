from legitifier_pkg.analyzers.code import CodeAnalyzer
from legitifier_pkg.core.models import HeuristicConfig, ScoringConfig

THRESHOLDS = {
    "api_patterns": ["from openai import", "api.mistral.ai", "openrouter.ai", "import anthropic"],
    "local_claim_patterns": ["run locally", "no api key", "fully local"],
    "extensions": [".py"],
}


def _config() -> HeuristicConfig:
    return HeuristicConfig(
        id="api_disguised_as_local",
        category="code_quality",
        weight=1.0,
        severity="critical",
        thresholds=THRESHOLDS,
        scoring=ScoringConfig(score_if_triggered=90, score_if_clean=0),
        evidence_template="API: {api_matches} | claims: {local_claims}",
    )


class TestCodeAnalyzer:
    def setup_method(self):
        self.analyzer = CodeAnalyzer()
        self.config = _config()

    def _data(self, code: str, readme: str) -> dict:
        return {"code_snippets": [{"path": "main.py", "content": code}], "readme": readme}

    def test_triggered_openai(self):
        data = self._data("from openai import OpenAI", "Run locally, no api key needed")
        assert self.analyzer.analyze(self.config, data).triggered

    def test_triggered_mistral(self):
        data = self._data("import requests\nurl = 'api.mistral.ai'", "fully local AI assistant")
        assert self.analyzer.analyze(self.config, data).triggered

    def test_triggered_openrouter(self):
        data = self._data("endpoint = 'openrouter.ai/api'", "run locally on your machine")
        assert self.analyzer.analyze(self.config, data).triggered

    def test_no_trigger_api_but_no_local_claim(self):
        data = self._data("from openai import OpenAI", "A GPT-4 wrapper with nice UI")
        assert not self.analyzer.analyze(self.config, data).triggered

    def test_no_trigger_local_claim_but_no_api(self):
        data = self._data("import torch\nmodel = AutoModel.from_pretrained('llama')", "run locally, no api key")
        assert not self.analyzer.analyze(self.config, data).triggered

    def test_clean_no_code(self):
        data = self._data("", "")
        result = self.analyzer.analyze(self.config, data)
        assert not result.triggered
        assert result.score == 0

    def test_raw_data_contains_matches(self):
        data = self._data("import anthropic", "fully local, no api key needed")
        result = self.analyzer.analyze(self.config, data)
        assert "import anthropic" in result.raw_data["api_matches"]
        assert result.raw_data["files_scanned"] == 1
