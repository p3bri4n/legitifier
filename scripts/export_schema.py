"""Export ScanReport JSON Schema to docs/scan_report.schema.json."""

from __future__ import annotations

import json
from pathlib import Path

from legitifier_pkg.core.models import ScanReport

out = Path(__file__).parents[1] / "docs" / "scan_report.schema.json"
out.parent.mkdir(exist_ok=True)
schema = ScanReport.model_json_schema()
out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
print(f"Schema written to {out}")
