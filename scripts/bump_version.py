#!/usr/bin/env python3
"""
Bump legitifier version to YYYY.MMDD.hhmm format and update pyproject.toml.

Usage:
    python scripts/bump_version.py           # bump to current datetime
    python scripts/bump_version.py --dry-run # preview without writing
"""
from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path

PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"
VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def current_version(content: str) -> str:
    match = VERSION_RE.search(content)
    if not match:
        raise ValueError("Could not find version in pyproject.toml")
    return match.group(1)


def new_version() -> str:
    now = datetime.now()
    return now.strftime("%Y.%m%d.%H%M")


def bump(dry_run: bool = False) -> None:
    content = PYPROJECT.read_text()
    old = current_version(content)
    new = new_version()

    if old == new:
        print(f"Version already up to date: {old}")
        return

    updated = VERSION_RE.sub(f'version = "{new}"', content, count=1)

    print(f"  {old}  →  {new}")

    if dry_run:
        print("[dry-run] pyproject.toml not written.")
        return

    PYPROJECT.write_text(updated)
    print("pyproject.toml updated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()
    bump(dry_run=args.dry_run)
