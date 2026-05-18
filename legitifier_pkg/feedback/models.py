from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from legitifier_pkg.core.models import ScanReport, Verdict


class Confidence(StrEnum):
    CERTAIN = "certain"
    PROBABLE = "probable"
    UNSURE = "unsure"


class FeedbackRecord(BaseModel):
    repo_url: str
    scan_report: ScanReport
    user_verdict: Verdict
    confidence: Confidence = Confidence.PROBABLE
    note: str | None = None
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    anonymous_user_id: str = ""  # set by store
