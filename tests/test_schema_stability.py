import json
from pathlib import Path

from legitifier_pkg.core.models import ScanReport

SCHEMA_PATH = Path(__file__).parents[1] / "docs" / "scan_report.schema.json"


def test_schema_matches_committed_version():
    current = json.dumps(ScanReport.model_json_schema(), indent=2, sort_keys=True)
    on_disk = json.dumps(json.loads(SCHEMA_PATH.read_text()), indent=2, sort_keys=True)
    assert current == on_disk, (
        "ScanReport schema has changed. Run `python scripts/export_schema.py` and commit."
    )
