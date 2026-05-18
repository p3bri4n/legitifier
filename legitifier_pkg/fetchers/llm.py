from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

_PROMPT_PATH = Path(__file__).parents[2] / "prompts" / "readme_analysis.txt"


@runtime_checkable
class LLMClient(Protocol):
    def complete(self, prompt: str) -> str:
        ...


class OpenAIClient:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=api_key)
            self._model = model
        except ImportError:
            raise ImportError("Install openai: pip install 'github-legitifier[llm]'")

    def complete(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=512,
        )
        return response.choices[0].message.content or ""


class AnthropicClient:
    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001") -> None:
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
            self._model = model
        except ImportError:
            raise ImportError("Install anthropic: pip install 'github-legitifier[llm]'")

    def complete(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class OllamaClient:
    """Ollama local LLM client — uses the OpenAI-compatible API endpoint."""

    def __init__(self, model: str = "qwen2.5:7b", base_url: str = "http://localhost:11434") -> None:
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key="ollama", base_url=f"{base_url}/v1")
            self._model = model
        except ImportError:
            raise ImportError("Install openai: pip install 'legitifier[llm]'")

    def complete(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=512,
        )
        return response.choices[0].message.content or ""


class LLMFetcher:
    def __init__(self, client: LLMClient, prompt_path: Path = _PROMPT_PATH) -> None:
        self._client = client
        self._template = prompt_path.read_text()

    def fetch(self, data: dict[str, Any]) -> dict[str, Any]:
        readme = (data.get("readme") or "")[:6000]  # cap tokens
        prompt = (
            self._template
            .replace("{{ title }}", data.get("slug", ""))
            .replace("{{ stars }}", str(data.get("stars", 0)))
            .replace("{{ topics }}", ", ".join(data.get("topics") or []))
            .replace("{{ readme }}", readme)
        )
        raw = self._client.complete(prompt)
        return {"llm_analysis": self._parse(raw)}

    @staticmethod
    def _parse(raw: str) -> dict[str, Any]:
        import re as _re
        # Remove markdown code fences
        cleaned = _re.sub(r"```json|```", "", raw).strip()
        # Try direct parse first
        try:
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            pass
        # Extract first {...} block from prose response
        match = _re.search(r'\{[^{}]*\}', cleaned, _re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except (json.JSONDecodeError, ValueError):
                pass
        # Try extracting largest {...} block
        matches = _re.findall(r'\{.*?\}', cleaned, _re.DOTALL)
        for m in sorted(matches, key=len, reverse=True):
            try:
                return json.loads(m)
            except (json.JSONDecodeError, ValueError):
                continue
        return {}


def client_from_env() -> LLMClient | None:
    """Auto-detect available LLM client from environment variables.

    Priority: OLLAMA_MODEL > OPENAI_API_KEY > ANTHROPIC_API_KEY

    Examples:
        OLLAMA_MODEL=qwen2.5:7b                        → Ollama local
        OLLAMA_MODEL=qwen2.5:7b OLLAMA_HOST=http://...  → Ollama remote
        OPENAI_API_KEY=sk-...                           → OpenAI
        ANTHROPIC_API_KEY=sk-ant-...                    → Anthropic
    """
    import os
    if model := os.getenv("OLLAMA_MODEL"):
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return OllamaClient(model=model, base_url=host)
    if key := os.getenv("OPENAI_API_KEY"):
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAIClient(api_key=key, model=model)
    if key := os.getenv("ANTHROPIC_API_KEY"):
        model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        return AnthropicClient(api_key=key, model=model)
    return None
