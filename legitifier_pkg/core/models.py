from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_SCAM = "LIKELY_SCAM"
    SCAM = "SCAM"
    UNKNOWN = "UNKNOWN"  # repo not found or fetch failed


class ScoringConfig(BaseModel):
    method: str = "linear"  # linear | step | sigmoid | weighted_average
    score_if_triggered: float = 0.0
    score_if_clean: float = 0.0
    weights: dict[str, float] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    enabled: bool = False
    prompt_template: str = ""
    output_format: str = "json"
    fields: list[dict[str, str]] = Field(default_factory=list)


class HeuristicConfig(BaseModel):
    id: str
    category: str
    weight: float = 1.0
    severity: Severity = Severity.MEDIUM
    description: str = ""
    inputs: list[str] = Field(default_factory=list)
    thresholds: dict[str, Any] = Field(default_factory=dict)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    evidence_template: str = ""
    tags: list[str] = Field(default_factory=list)
    llm: LLMConfig | None = None


class HeuristicResult(BaseModel):
    heuristic_id: str
    score: float = Field(ge=0.0, le=100.0)
    triggered: bool
    evidence: str
    severity: Severity
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    repo_url: str
    final_score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    results: list[HeuristicResult]
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    errors: list[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @classmethod
    def verdict_from_score(cls, score: float) -> Verdict:
        if score < 25:
            return Verdict.CLEAN
        if score < 50:
            return Verdict.SUSPICIOUS
        if score < 75:
            return Verdict.LIKELY_SCAM
        return Verdict.SCAM
