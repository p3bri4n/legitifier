from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel


class ReputationVerdict(StrEnum):
    SCAM = "SCAM"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"


class ReputationConfidence(StrEnum):
    CERTAIN = "certain"
    PROBABLE = "probable"
    UNSURE = "unsure"


class ReputationEntry(BaseModel):
    type: Literal["owner", "repo", "contributor"]
    login: str | None = None        # for owner/contributor
    slug: str | None = None         # for repo (owner/repo)
    verdict: ReputationVerdict
    confidence: ReputationConfidence = ReputationConfidence.PROBABLE
    source: str = "manual"          # manual | wall-of-shames | starscout | user
    note: str | None = None
    added: date
    supersedes: str | None = None   # login or slug of entry this overrides

    @property
    def key(self) -> str:
        return self.slug or self.login or ""
