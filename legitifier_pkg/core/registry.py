from __future__ import annotations

from pathlib import Path

import yaml

from legitifier_pkg.core.models import HeuristicConfig

_HEURISTICS_ROOT = Path(__file__).parents[2] / "heuristics"


class HeuristicRegistry:
    def __init__(self, root: Path = _HEURISTICS_ROOT) -> None:
        self._root = root
        self._heuristics: dict[str, HeuristicConfig] = {}

    def load(self) -> None:
        self._heuristics.clear()
        for path in self._root.rglob("*.yaml"):
            config = self._load_file(path)
            if config.id in self._heuristics:
                raise ValueError(f"Duplicate heuristic id: {config.id} in {path}")
            self._heuristics[config.id] = config

    def _load_file(self, path: Path) -> HeuristicConfig:
        with path.open() as f:
            data = yaml.safe_load(f)
        return HeuristicConfig.model_validate(data)

    def all(self) -> list[HeuristicConfig]:
        return list(self._heuristics.values())

    def by_category(self, category: str) -> list[HeuristicConfig]:
        return [h for h in self._heuristics.values() if h.category == category]

    def get(self, heuristic_id: str) -> HeuristicConfig:
        try:
            return self._heuristics[heuristic_id]
        except KeyError:
            raise KeyError(f"Unknown heuristic: {heuristic_id}")

    @property
    def categories(self) -> set[str]:
        return {h.category for h in self._heuristics.values()}
