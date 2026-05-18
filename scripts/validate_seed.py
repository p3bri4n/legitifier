"""
scripts/validate_seed.py — Validate data/seed.jsonl before committing or merging.

Checks:
  - Valid JSON on every non-comment line
  - Required fields present
  - No modification or deletion of existing entries (append-only)
  - 'certain' confidence requires an external source
  - Dates are valid ISO format
  - No duplicate keys

Usage:
    python scripts/validate_seed.py                    # validate current seed
    python scripts/validate_seed.py --against main     # compare with main branch (CI mode)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

SEED_PATH = Path(__file__).parents[1] / "data" / "seed.jsonl"

REQUIRED_FIELDS = {"type", "verdict", "confidence", "source", "note", "added"}
VALID_TYPES = {"owner", "repo", "contributor"}
VALID_VERDICTS = {"SCAM", "SUSPICIOUS", "CLEAN"}
VALID_CONFIDENCES = {"certain", "probable", "unsure"}
EXTERNAL_SOURCES = {"wall-of-shames", "starscout", "community"}

Errors = list[str]


def _load_lines(path: Path) -> list[tuple[int, str]]:
    """Return (line_number, raw_line) for non-comment, non-blank lines."""
    result = []
    for i, line in enumerate(path.read_text().splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            result.append((i, stripped))
    return result


def validate_entry(lineno: int, raw: str) -> tuple[dict | None, Errors]:
    errors: Errors = []

    try:
        entry = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, [f"Line {lineno}: invalid JSON — {e}"]

    # Required fields
    missing = REQUIRED_FIELDS - entry.keys()
    if missing:
        errors.append(f"Line {lineno}: missing fields: {missing}")

    # type
    if entry.get("type") not in VALID_TYPES:
        errors.append(f"Line {lineno}: invalid type '{entry.get('type')}' — must be one of {VALID_TYPES}")

    # login or slug required depending on type
    if entry.get("type") in ("owner", "contributor") and not entry.get("login"):
        errors.append(f"Line {lineno}: 'login' required for type '{entry.get('type')}'")
    if entry.get("type") == "repo" and not entry.get("slug"):
        errors.append(f"Line {lineno}: 'slug' required for type 'repo'")
    if entry.get("type") == "repo" and entry.get("slug") and "/" not in entry["slug"]:
        errors.append(f"Line {lineno}: 'slug' must be 'owner/repo' format")

    # verdict
    if entry.get("verdict") not in VALID_VERDICTS:
        errors.append(f"Line {lineno}: invalid verdict '{entry.get('verdict')}'")

    # confidence
    if entry.get("confidence") not in VALID_CONFIDENCES:
        errors.append(f"Line {lineno}: invalid confidence '{entry.get('confidence')}'")

    # certain requires external source — except for CLEAN entries (whitelist)
    if (entry.get("confidence") == "certain"
            and entry.get("verdict") != "CLEAN"
            and entry.get("source") not in EXTERNAL_SOURCES):
        errors.append(
            f"Line {lineno}: confidence 'certain' requires an external source "
            f"({EXTERNAL_SOURCES}), got '{entry.get('source')}'. "
            f"Use 'probable' for manual entries without external proof. "
            f"Exception: 'certain' is allowed for verdict=CLEAN (whitelist entries)."
        )

    # note must be non-empty
    if not entry.get("note", "").strip():
        errors.append(f"Line {lineno}: 'note' must not be empty")

    # date format
    try:
        date.fromisoformat(str(entry.get("added", "")))
    except ValueError:
        errors.append(f"Line {lineno}: 'added' must be a valid ISO date (YYYY-MM-DD)")

    return entry, errors


def validate_file(path: Path) -> tuple[list[dict], Errors]:
    lines = _load_lines(path)
    all_errors: Errors = []
    entries = []
    seen_keys: dict[str, int] = {}

    for lineno, raw in lines:
        entry, errors = validate_entry(lineno, raw)
        all_errors.extend(errors)
        if entry is None:
            continue

        key = entry.get("slug") or entry.get("login") or ""
        if key in seen_keys:
            all_errors.append(
                f"Line {lineno}: duplicate key '{key}' (first seen at line {seen_keys[key]})"
            )
        else:
            seen_keys[key] = lineno
            entries.append(entry)

    return entries, all_errors


def validate_append_only(path: Path, base_branch: str = "main") -> Errors:
    """Ensure no existing entries were modified or deleted."""
    errors: Errors = []
    try:
        result = subprocess.run(
            ["git", "show", f"{base_branch}:{path.relative_to(Path.cwd())}"],
            capture_output=True, text=True, check=True,
        )
        base_content = result.stdout
    except subprocess.CalledProcessError:
        return []  # base branch doesn't have the file yet — OK

    base_lines = {
        line.strip() for line in base_content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    current_lines = {
        line.strip() for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    removed = base_lines - current_lines
    for line in removed:
        try:
            entry = json.loads(line)
            key = entry.get("slug") or entry.get("login")
            errors.append(f"Append-only violation: entry '{key}' was removed or modified.")
        except json.JSONDecodeError:
            errors.append("Append-only violation: a line was removed or modified.")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--against", metavar="BRANCH",
                        help="Check append-only against this branch (e.g. main)")
    parser.add_argument("--seed", type=Path, default=SEED_PATH,
                        help="Path to seed file")
    args = parser.parse_args()

    print(f"Validating {args.seed}...")
    entries, errors = validate_file(args.seed)

    if args.against:
        errors += validate_append_only(args.seed, args.against)

    if errors:
        print(f"\n❌ {len(errors)} error(s) found:\n")
        for err in errors:
            print(f"  • {err}")
        return 1

    print(f"✅ {len(entries)} valid entries — no issues found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
