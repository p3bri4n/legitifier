from __future__ import annotations

from pathlib import Path
from typing import Any

from legitifier_pkg.data.loader import ReputationStore


class LocalDBFetcher:
    """
    Enriches repo data with reputation scores from:
    - data/seed.jsonl (public seed)
    - ~/.legitifier/scans.db reputation table (user-local)

    Adds to data{}:
      owner_reputation:         {score, verdict, confidence, note}
      contributor_reputation:   {score, flagged_logins, sample_size}
    """

    def __init__(
        self, store: ReputationStore | None = None, db_path: Path | None = None
    ) -> None:
        self._store = store or ReputationStore(db_path=db_path)

    def fetch(self, data: dict[str, Any]) -> dict[str, Any]:
        slug: str = data.get("slug", "")
        owner = slug.split("/")[0] if "/" in slug else ""

        result: dict[str, Any] = {
            "owner_reputation": self._owner_rep(owner, slug),
            "contributor_reputation": self._contributor_rep(data),
        }
        return result

    def _owner_rep(self, owner: str, slug: str) -> dict[str, Any]:
        # Check repo slug first (more specific), then owner
        entry = self._store.lookup(slug) or self._store.lookup(owner)
        if not entry:
            return {"score": 0.0, "verdict": None, "confidence": None, "note": None}
        return {
            "score": self._store.score(entry.key),
            "verdict": entry.verdict.value,
            "confidence": entry.confidence.value,
            "note": entry.note,
        }

    def _contributor_rep(self, data: dict[str, Any]) -> dict[str, Any]:
        prs: list[dict] = data.get("recent_prs", [])
        if not prs:
            return {"score": 0.0, "flagged_logins": [], "sample_size": 0}

        logins = {pr.get("user_login") for pr in prs if pr.get("user_login")}
        flagged = []
        for login in logins:
            entry = self._store.lookup(login)
            if entry and entry.verdict.value in ("SCAM", "SUSPICIOUS"):
                flagged.append(
                    {
                        "login": login,
                        "verdict": entry.verdict.value,
                        "confidence": entry.confidence.value,
                    }
                )

        # Score proportional to ratio of flagged contributors
        ratio = len(flagged) / len(logins) if logins else 0.0
        score = round(min(ratio * 100, 90.0), 1)
        return {"score": score, "flagged_logins": flagged, "sample_size": len(logins)}
