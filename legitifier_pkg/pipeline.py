from __future__ import annotations

from typing import Any

from rich.console import Console

import legitifier_pkg.analyzers.code  # noqa: F401 — registers analyzer
import legitifier_pkg.analyzers.content  # noqa: F401
import legitifier_pkg.analyzers.metadata  # noqa: F401
import legitifier_pkg.analyzers.repo_history  # noqa: F401
import legitifier_pkg.analyzers.social  # noqa: F401
from legitifier_pkg.analyzers.base import get_analyzer
from legitifier_pkg.core.models import HeuristicResult, ScanReport, Verdict
from legitifier_pkg.core.registry import HeuristicRegistry
from legitifier_pkg.core.scorer import Scorer
from legitifier_pkg.data.loader import ReputationStore
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.fetchers.github import GitHubFetcher
from legitifier_pkg.fetchers.llm import LLMClient, LLMFetcher
from legitifier_pkg.fetchers.local_db import LocalDBFetcher

console = Console()


class Pipeline:
    def __init__(
        self,
        github_token: str | None = None,
        llm_client: LLMClient | None = None,
        registry: HeuristicRegistry | None = None,
        scorer: Scorer | None = None,
        store: FeedbackStore | None = None,
        silent: bool = False,
    ) -> None:
        self._github = GitHubFetcher(token=github_token)
        self._llm = LLMFetcher(llm_client) if llm_client else None
        self._local_db = LocalDBFetcher(
            store=ReputationStore(db_path=store._path if store else None)
        )
        self._registry = registry or HeuristicRegistry()
        self._scorer = scorer or Scorer()
        self._store = store or FeedbackStore()
        self._silent = silent  # disable progress in tests / batch mode

    def run(self, repo_url: str) -> tuple[ScanReport, int]:
        """Returns (report, scan_id) — scan_id used to attach feedback later."""
        import time

        self._registry.load()

        errors: list[str] = []
        data: dict[str, Any] = {}
        started_at = time.monotonic()

        def _step(msg: str) -> None:
            if not self._silent:
                console.print(f"[dim]⠋ {msg}[/]", end="\r")

        with console.status("", spinner="dots") if not self._silent else _NullContext():
            _step("Fetching repository data...")
            fetch_error: Exception | None = None
            try:
                data = self._github.fetch(repo_url)
            except Exception as exc:
                fetch_error = exc
                errors.append(f"GitHub fetch error: {exc}")

            # Detect 404 early — don't score empty data as CLEAN
            if fetch_error and "404" in str(fetch_error):
                elapsed = round(time.monotonic() - started_at, 1)
                report = ScanReport(
                    repo_url=repo_url,
                    risk_score=0.0,
                    verdict=Verdict.UNKNOWN,
                    results=[],
                    errors=errors,
                    scan_duration_seconds=elapsed,
                )
                scan_id = self._store.save_scan(report)
                return report, scan_id

            if self._llm:
                _step("Analyzing README with LLM...")
                try:
                    data.update(self._llm.fetch(data))
                except Exception as exc:
                    errors.append(f"LLM fetch error: {exc}")

            _step("Checking reputation database...")
            try:
                data.update(self._local_db.fetch(data))
            except Exception as exc:
                errors.append(f"LocalDB fetch error: {exc}")

            _step("Running heuristics...")
            results: list[HeuristicResult] = []
            for config in self._registry.all():
                try:
                    analyzer = get_analyzer(config.category)
                    result = analyzer.analyze(config, data)
                    results.append(result)
                except KeyError as exc:
                    errors.append(str(exc))
                except Exception as exc:
                    errors.append(f"Analyzer error [{config.id}]: {exc}")

        elapsed = round(time.monotonic() - started_at, 1)
        whitelisted = data.get("owner_reputation", {}).get("verdict") == "CLEAN"
        report = self._scorer.aggregate(
            repo_url, results, errors, whitelisted=whitelisted, duration=elapsed
        )
        scan_id = self._store.save_scan(report)
        # Propagate reputation from scam contributors
        self._store.record_contributor_reputation(report)
        return report, scan_id


class _NullContext:
    def __enter__(self) -> _NullContext:
        return self

    def __exit__(self, *_: object) -> None:
        pass
