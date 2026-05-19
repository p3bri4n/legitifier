from legitifier_pkg.analyzers.code import CodeAnalyzer, _extract_code_only
from legitifier_pkg.core.models import HeuristicConfig, ScoringConfig

THRESHOLDS = {
    "api_patterns": [
        "from openai import",
        "api.mistral.ai",
        "openrouter.ai",
        "import anthropic",
    ],
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
        return {
            "code_snippets": [{"path": "main.py", "content": code}],
            "readme": readme,
        }

    def test_triggered_openai(self):
        data = self._data("from openai import OpenAI", "Run locally, no api key needed")
        assert self.analyzer.analyze(self.config, data).triggered

    def test_triggered_mistral(self):
        data = self._data(
            "import requests\nurl = 'api.mistral.ai'", "fully local AI assistant"
        )
        assert self.analyzer.analyze(self.config, data).triggered

    def test_triggered_openrouter(self):
        data = self._data(
            "endpoint = 'openrouter.ai/api'", "run locally on your machine"
        )
        assert self.analyzer.analyze(self.config, data).triggered

    def test_no_trigger_api_but_no_local_claim(self):
        data = self._data("from openai import OpenAI", "A GPT-4 wrapper with nice UI")
        assert not self.analyzer.analyze(self.config, data).triggered

    def test_no_trigger_local_claim_but_no_api(self):
        data = self._data(
            "import torch\nmodel = AutoModel.from_pretrained('llama')",
            "run locally, no api key",
        )
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


class TestExtractCodeOnly:
    def _snippet(self, content: str, path: str = "main.py") -> dict:
        return {"path": path, "content": content}

    def test_api_pattern_in_comment_is_ignored(self):
        code = "# We don't use openai.com here\nx = 1"
        result = _extract_code_only(self._snippet(code))
        assert "openai" not in result

    def test_api_pattern_in_docstring_is_ignored(self):
        code = '"""See openai.com for context."""\nx = 1'
        result = _extract_code_only(self._snippet(code))
        assert "openai" not in result

    def test_real_import_is_kept(self):
        code = "from openai import OpenAI\nclient = OpenAI()"
        result = _extract_code_only(self._snippet(code))
        assert "from openai import OpenAI" in result

    def test_malformed_python_falls_back_gracefully(self):
        code = "def foo(\n# unclosed — syntax error\nurl = 'api.mistral.ai'"
        result = _extract_code_only(self._snippet(code))
        # No crash; comments are still stripped via fallback
        assert "# unclosed" not in result
        assert "api.mistral.ai" in result

    def test_non_python_comment_lines_stripped(self):
        code = "// not openai\nconst x = 1;"
        result = _extract_code_only(self._snippet(code, path="main.js"))
        assert "openai" not in result
        assert "const x = 1;" in result

    def test_multiline_docstring_fully_removed(self):
        code = '"""Line one.\nopenai.com mentioned here.\nLine three.\n"""\nx = 1'
        result = _extract_code_only(self._snippet(code))
        assert "openai" not in result
        assert "x = 1" in result


class TestApiDisguisedIntegration:
    """Integration tests verifying the full heuristic with comment/docstring filtering."""

    def setup_method(self):
        self.analyzer = CodeAnalyzer()
        self.config = _config()

    def _data(self, code: str, readme: str, path: str = "main.py") -> dict:
        return {
            "code_snippets": [{"path": path, "content": code}],
            "readme": readme,
        }

    def test_api_in_comment_does_not_trigger(self):
        code = "# from openai import OpenAI\nx = 1"
        data = self._data(code, "run locally, no api key")
        assert not self.analyzer.analyze(self.config, data).triggered

    def test_api_in_docstring_does_not_trigger(self):
        code = '"""This project does NOT use openai.com."""\nx = 1'
        data = self._data(code, "fully local, no api key needed")
        assert not self.analyzer.analyze(self.config, data).triggered

    def test_real_import_still_triggers(self):
        code = "from openai import OpenAI\nclient = OpenAI()"
        data = self._data(code, "run locally, no api key")
        assert self.analyzer.analyze(self.config, data).triggered

    def test_syntax_error_falls_back_no_crash(self):
        code = "def foo(\n# syntax error\nfrom openai import OpenAI"
        data = self._data(code, "fully local, no api key needed")
        # Must not raise — result can be either triggered or not
        result = self.analyzer.analyze(self.config, data)
        assert isinstance(result.triggered, bool)
