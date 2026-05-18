from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult

_ANALYZER_REGISTRY: dict[str, type[BaseAnalyzer]] = {}


def analyzer_for(category: str):
    """Class decorator to register an analyzer for a heuristic category."""
    def decorator(cls: type[BaseAnalyzer]) -> type[BaseAnalyzer]:
        _ANALYZER_REGISTRY[category] = cls
        return cls
    return decorator


def get_analyzer(category: str) -> BaseAnalyzer:
    cls = _ANALYZER_REGISTRY.get(category)
    if cls is None:
        raise KeyError(f"No analyzer registered for category: {category!r}")
    return cls()


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        ...

    def _render_evidence(self, template: str, context: dict[str, Any]) -> str:
        try:
            return template.format(**context)
        except KeyError:
            return template
