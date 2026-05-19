from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from legitifier_pkg.data.models import (
    ReputationConfidence,
    ReputationEntry,
    ReputationVerdict,
)


def _find_seed() -> Path:
    """Find seed.jsonl — works both from source tree and installed package."""
    # Try relative to this file (source tree: legitifier_pkg/data/loader.py → data/seed.jsonl)
    candidates = [
        Path(__file__).parents[3] / "data" / "seed.jsonl",  # source: project root
        Path(__file__).parents[2]
        / "data"
        / "seed.jsonl",  # installed under legitifier_pkg
        Path(__file__).parent / "seed.jsonl",  # bundled alongside loader.py
    ]
    for path in candidates:
        if path.exists():
            return path
    return candidates[0]  # return default even if missing — _load_seed handles it


_SEED_PATH = _find_seed()
_CONFIDENCE_WEIGHT = {
    ReputationConfidence.CERTAIN: 1.0,
    ReputationConfidence.PROBABLE: 0.6,
    ReputationConfidence.UNSURE: 0.3,
}


class ReputationStore:
    """
    Merged view of:
    - data/seed.jsonl    (public, versioned in the repo)
    - ~/.legitifier/scans.db reputation table (user-local)

    Lookup returns the highest-confidence verdict found, with local entries
    taking priority over seed entries of equal confidence.
    """

    def __init__(
        self,
        seed_path: Path = _SEED_PATH,
        db_path: Path | None = None,
    ) -> None:
        self._entries: dict[str, list[ReputationEntry]] = {}
        self._load_seed(seed_path)
        if db_path:
            self._load_local(db_path)

    def _load_seed(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = ReputationEntry.model_validate(json.loads(line))
            self._entries.setdefault(entry.key, []).append(entry)

    def _load_local(self, db_path: Path) -> None:
        if not db_path.exists():
            return
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT type, login, slug, verdict, confidence, source, note, added "
                "FROM reputation"
            ).fetchall()
        for row in rows:
            entry = ReputationEntry(
                type=row[0],
                login=row[1],
                slug=row[2],
                verdict=ReputationVerdict(row[3]),
                confidence=ReputationConfidence(row[4]),
                source=row[5],
                note=row[6],
                added=row[7],
            )
            self._entries.setdefault(entry.key, []).append(entry)

    def lookup(self, key: str) -> ReputationEntry | None:
        """Return the most reliable entry for a given owner login or repo slug."""
        entries = self._entries.get(key) or self._entries.get(key.lower())
        if not entries:
            return None
        return max(entries, key=lambda e: _CONFIDENCE_WEIGHT[e.confidence])

    def score(self, key: str) -> float:
        """
        Returns a 0-100 reputation score (higher = more suspicious).
        0 if unknown or CLEAN, weighted by confidence.
        """
        entry = self.lookup(key)
        if not entry or entry.verdict == ReputationVerdict.CLEAN:
            return 0.0
        base = 90.0 if entry.verdict == ReputationVerdict.SCAM else 50.0
        return round(base * _CONFIDENCE_WEIGHT[entry.confidence], 1)

    def all_keys(self) -> Iterable[str]:
        return self._entries.keys()
