import filecmp
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_seed_files_are_in_sync():
    src = ROOT / "data" / "seed.jsonl"
    dst = ROOT / "legitifier_pkg" / "data" / "seed.jsonl"
    assert filecmp.cmp(src, dst, shallow=False), (
        "Files diverged. Run: python scripts/sync_data.py"
    )


def test_search_presets_are_in_sync():
    src = ROOT / "data" / "search_presets.yaml"
    dst = ROOT / "legitifier_pkg" / "search_presets.yaml"
    assert filecmp.cmp(src, dst, shallow=False), (
        "Files diverged. Run: python scripts/sync_data.py"
    )
