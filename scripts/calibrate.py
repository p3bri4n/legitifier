#!/usr/bin/env python3
"""
scripts/calibrate.py — Collect calibration data for heuristic tuning.

Scans a mix of known-legitimate and suspected repos, then produces a
calibration report showing which heuristics trigger on each category.

Usage:
    python scripts/calibrate.py
    python scripts/calibrate.py --skip-legit    # only scan suspects
    python scripts/calibrate.py --skip-suspects # only scan legit baseline
    python scripts/calibrate.py --report        # report only, no new scans

Output:
    calibration_report.json  — raw data
    calibration_report.md    — human-readable summary
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from legitifier_pkg import __version__
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.fetchers.llm import client_from_env
from legitifier_pkg.pipeline import Pipeline
from legitifier_pkg.search import starscout_repos, trending_repos

# ── Known-legitimate repos (manually curated baseline) ────────────────────────
LEGIT_REPOS = [
    # Popular, well-established
    "github.com/psf/black",
    "github.com/tartley/colorama",
    "github.com/tiangolo/fastapi",
    "github.com/pallets/flask",
    "github.com/encode/httpx",
    "github.com/tqdm/tqdm",
    "github.com/python-poetry/poetry",
    "github.com/astral-sh/ruff",
    "github.com/pydantic/pydantic",
    "github.com/pytest-dev/pytest",
    # Small but genuine
    "github.com/willmcgugan/rich",
    "github.com/Textualize/textual",
    "github.com/tiangolo/typer",
    "github.com/charmbracelet/gum",
    "github.com/BurntSushi/ripgrep",
]

# Educational repos — honest learning projects, low forks expected
EDUCATIONAL_REPOS = [
    "github.com/p3bri4n/risc-v-32-edu",   # RV32I simulator in Python
    "github.com/nand2tetris/nand2tetris",  # From Nand to Tetris course
    "github.com/karpathy/micrograd",       # Educational autograd engine
    "github.com/karpathy/makemore",        # Educational language model
    "github.com/fastai/fastbook",          # Deep learning course notebooks
    "github.com/karpathy/ng-video-lecture", # Neural nets from scratch
]

DELAY = 6.0  # seconds between scans


def _make_pipeline(token: str | None) -> Pipeline:
    store = FeedbackStore()
    return Pipeline(
        github_token=token or os.getenv("GITHUB_TOKEN"),
        llm_client=client_from_env(),
        store=store,
        silent=True,
    )


def scan_repo(pipeline: Pipeline, url: str, category: str, store: FeedbackStore) -> dict | None:
    existing = store.get_recent_scan(url, max_age_seconds=6 * 3600, current_version=__version__)
    if existing:
        triggered = [r.heuristic_id for r in existing.results if r.triggered]
        trust = round(100 - existing.risk_score, 1)
        print(
            f"  {'✅' if existing.verdict.value == 'CLEAN' else '🚩'} "
            f"{existing.verdict.value:12} Trust {trust:3.0f}  "
            f"{url.split('github.com/')[-1]}  (cached)"
            + (f"  [{', '.join(triggered)}]" if triggered else "")
        )
        return {
            "url": url, "category": category, "cached": True,
            "verdict": existing.verdict.value,
            "risk_score": existing.risk_score, "trust": trust,
            "triggered": triggered,
            "scores": {r.heuristic_id: r.score for r in existing.results},
        }

    try:
        report, _ = pipeline.run(url)
        triggered = [r.heuristic_id for r in report.results if r.triggered]
        print(
            f"  {'✅' if report.verdict.value == 'CLEAN' else '🚩'} "
            f"{report.verdict.value:12} Trust {100 - report.risk_score:3.0f}  "
            f"{url.split('github.com/')[-1]}"
            + (f"  [{', '.join(triggered)}]" if triggered else "")
        )
        return {
            "url": url, "category": category, "cached": False,
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "trust": round(100 - report.risk_score, 1),
            "triggered": triggered,
            "scores": {r.heuristic_id: r.score for r in report.results},
        }
    except Exception as e:
        print(f"  ❌ ERROR  {url.split('github.com/')[-1]}: {e}")
        return None


def collect(args) -> list[dict]:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("⚠️  GITHUB_TOKEN not set — scans will be slow.\n")

    store = FeedbackStore()
    pipeline = _make_pipeline(token)
    results: list[dict] = []

    if not args.skip_legit:
        print(f"\n{'═' * 60}")
        print("📋 LEGIT BASELINE — known legitimate repos")
        print(f"{'═' * 60}")
        for url in LEGIT_REPOS:
            r = scan_repo(pipeline, url, "legit", store)
            if r:
                results.append(r)
            if not r or not r.get('cached'):
                time.sleep(DELAY)

        print(f"\n{'─' * 60}")
        print("📋 LEGIT TRENDING — GitHub Trending (daily)")
        print(f"{'─' * 60}")
        for url, _ in trending_repos(limit=30):
            if url.startswith("__"):
                continue
            r = scan_repo(pipeline, url, "legit_trending", store)
            if r:
                results.append(r)
            if not r or not r.get('cached'):
                time.sleep(DELAY)

        print(f"\n{'─' * 60}")
        print("📚 EDUCATIONAL REPOS — honest learning/tutorial projects")
        print(f"{'─' * 60}")
        for url in EDUCATIONAL_REPOS:
            r = scan_repo(pipeline, url, "educational", store)
            if r:
                results.append(r)
            if not r or not r.get("cached"):
                time.sleep(DELAY)
        print(f"\n{'═' * 60}")
        print("🚨 SUSPECTS — CMU StarScout dataset")
        print(f"{'═' * 60}")
        count = 0
        for url, _ in starscout_repos(limit=200):
            if url.startswith("__"):
                print(f"  ❌ {url}")
                break
            r = scan_repo(pipeline, url, "starscout", store)
            if r:
                results.append(r)
                count += 1
            if count >= 30:
                break
            time.sleep(DELAY)

        print(f"\n{'─' * 60}")
        print("🚨 SUSPECTS — WormGPT variants")
        print(f"{'─' * 60}")
        from legitifier_pkg.search import search_repos
        count = 0
        for url, _ in search_repos("topic:worm-gpt OR topic:darkgpt stars:>10", token, 50):
            if url.startswith("__"):
                break
            r = scan_repo(pipeline, url, "wormgpt", store)
            if r:
                results.append(r)
                count += 1
            if count >= 20:
                break
            time.sleep(DELAY)

    return results


def report(results: list[dict]) -> None:
    if not results:
        print("No results to report.")
        return

    legit = [r for r in results if r["category"] in ("legit", "legit_trending", "educational")]
    suspects = [r for r in results if r["category"] in ("starscout", "wormgpt")]

    # Collect all heuristic IDs
    all_heuristics = sorted({h for r in results for h in r["scores"]})

    lines = ["# Calibration Report\n"]
    lines.append(f"**{len(legit)} legitimate** | **{len(suspects)} suspected**\n")

    # False positive rate per heuristic
    lines.append("## False Positive Rate (triggered on legit repos)\n")
    lines.append("| Heuristic | Legit triggered | FP rate | Suspect triggered | Detection rate |")
    lines.append("|-----------|----------------|---------|-------------------|----------------|")

    fp_data = []
    for h in all_heuristics:
        legit_triggered = sum(1 for r in legit if h in r["triggered"])
        suspect_triggered = sum(1 for r in suspects if h in r["triggered"])
        fp_rate = legit_triggered / len(legit) if legit else 0
        det_rate = suspect_triggered / len(suspects) if suspects else 0
        fp_data.append((h, legit_triggered, fp_rate, suspect_triggered, det_rate))
        flag = " ⚠️" if fp_rate > 0.2 else ""
        lines.append(
            f"| `{h}` | {legit_triggered}/{len(legit)} | {fp_rate:.0%}{flag} "
            f"| {suspect_triggered}/{len(suspects)} | {det_rate:.0%} |"
        )

    # Trust score distribution
    lines.append("\n## Trust Score Distribution\n")
    lines.append("| Category | Min | Median | Max | CLEAN | SUSPICIOUS | LIKELY_SCAM | SCAM |")
    lines.append("|----------|-----|--------|-----|-------|------------|-------------|------|")

    for label, group in [("Legit", legit), ("Suspects", suspects)]:
        if not group:
            continue
        scores = sorted(r["trust"] for r in group)
        verdicts = [r["verdict"] for r in group]
        lines.append(
            f"| {label} | {scores[0]:.0f} | {scores[len(scores)//2]:.0f} | {scores[-1]:.0f} "
            f"| {verdicts.count('CLEAN')} | {verdicts.count('SUSPICIOUS')} "
            f"| {verdicts.count('LIKELY_SCAM')} | {verdicts.count('SCAM')} |"
        )

    # High FP heuristics
    high_fp = [(h, fp, det) for h, _, fp, _, det in fp_data if fp > 0.15]
    if high_fp:
        lines.append("\n## ⚠️ Heuristics with high false positive rate (>15%)\n")
        for h, fp, det in high_fp:
            lines.append(f"- **`{h}`** — FP rate: {fp:.0%}, Detection rate: {det:.0%}")
            lines.append("  → Consider raising threshold or adding `min_stars` guard")

    md = "\n".join(lines)
    print("\n" + md)

    # Write files
    out_json = Path("calibration_report.json")
    out_md = Path("calibration_report.md")
    out_json.write_text(json.dumps(results, indent=2))
    out_md.write_text(md)
    print(f"\n✅ Saved: {out_json} and {out_md}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-legit", action="store_true", help="Skip legitimate baseline scans")
    parser.add_argument("--skip-suspects", action="store_true", help="Skip suspect scans")
    parser.add_argument("--report", action="store_true",
                        help="Generate report from existing calibration_report.json")
    args = parser.parse_args()

    if args.report:
        path = Path("calibration_report.json")
        if not path.exists():
            print("No calibration_report.json found. Run without --report first.")
            sys.exit(1)
        results = json.loads(path.read_text())
        report(results)
        return

    total = (len(LEGIT_REPOS) + 30 + 50) if not args.skip_legit else 0
    total += 50 if not args.skip_suspects else 0
    eta = total * (DELAY + 10) / 60
    print(f"🔍 Calibration scan — estimated {eta:.0f} minutes")
    print(f"   Token: {'✅' if os.getenv('GITHUB_TOKEN') else '❌ not set'}")
    print("   Press Ctrl+C to stop early — partial results will still be reported.\n")

    results = []
    try:
        results = collect(args)
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted — generating partial report...")

    if results:
        report(results)
    else:
        print("No results collected.")


if __name__ == "__main__":
    main()
