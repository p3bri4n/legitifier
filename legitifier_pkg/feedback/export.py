from __future__ import annotations

import json
from pathlib import Path

from legitifier_pkg.feedback.store import FeedbackStore


def export_jsonl(output: Path, store: FeedbackStore | None = None) -> int:
    """Export annotated scans as JSONL for model training. Returns record count."""
    store = store or FeedbackStore()
    records = store.export_annotated()

    with output.open("w") as f:
        for record in records:
            row = {
                "repo_url": record.repo_url,
                "final_score": record.scan_report.final_score,
                "auto_verdict": record.scan_report.verdict.value,
                "user_verdict": record.user_verdict.value,
                "confidence": record.confidence.value,
                "note": record.note,
                "readme": next(
                    (r.raw_data.get("readme", "") for r in record.scan_report.results if "readme" in r.raw_data),
                    "",
                ),
                "heuristic_scores": {r.heuristic_id: r.score for r in record.scan_report.results},
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return len(records)
