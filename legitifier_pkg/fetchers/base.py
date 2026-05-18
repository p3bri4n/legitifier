from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Fetcher(Protocol):
    def fetch(self, **kwargs: Any) -> dict[str, Any]:
        ...
