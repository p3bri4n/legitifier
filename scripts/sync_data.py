#!/usr/bin/env python3
"""Synchronize data/ files into legitifier_pkg/ for packaging.

`data/seed.jsonl` and `data/search_presets.yaml` are the source of truth.
This script copies them into the package directory.

Usage:
    python scripts/sync_data.py           # write
    python scripts/sync_data.py --check   # exit 1 if out of sync (CI)
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
PAIRS = [
    (ROOT / "data" / "seed.jsonl", ROOT / "legitifier_pkg" / "data" / "seed.jsonl"),
    (
        ROOT / "data" / "search_presets.yaml",
        ROOT / "legitifier_pkg" / "search_presets.yaml",
    ),
]


def main(check: bool) -> int:
    out_of_sync = []
    for src, dst in PAIRS:
        if not src.exists():
            print(f"❌ Source missing: {src}", file=sys.stderr)
            return 2
        if not dst.exists() or not filecmp.cmp(src, dst, shallow=False):
            out_of_sync.append((src, dst))

    if check:
        if out_of_sync:
            print("❌ Out-of-sync files:", file=sys.stderr)
            for src, dst in out_of_sync:
                print(f"   {dst} != {src}", file=sys.stderr)
            print("\nRun: python scripts/sync_data.py", file=sys.stderr)
            return 1
        print("✅ All data files in sync.")
        return 0

    for src, dst in out_of_sync:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"✅ {src} → {dst}")
    if not out_of_sync:
        print("✅ Already in sync.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    sys.exit(main(args.check))
