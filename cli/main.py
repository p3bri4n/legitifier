from __future__ import annotations

import os
from datetime import UTC
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from legitifier_pkg.core.models import Verdict
from legitifier_pkg.feedback.models import Confidence
from legitifier_pkg.feedback.store import FeedbackStore
from legitifier_pkg.fetchers.llm import client_from_env
from legitifier_pkg.pipeline import Pipeline
from legitifier_pkg.reports import terminal as terminal_report
from legitifier_pkg.reports.terminal import trust_score

app = typer.Typer(help="Evaluate the credibility of GitHub repositories.")
console = Console()

_VERDICT_COLOR = {
    Verdict.CLEAN: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.LIKELY_SCAM: "orange3",
    Verdict.SCAM: "red",
    Verdict.UNKNOWN: "dim",
}
_VERDICT_ICON = {
    Verdict.CLEAN: "✅",
    Verdict.SUSPICIOUS: "⚠️ ",
    Verdict.LIKELY_SCAM: "🚨",
    Verdict.SCAM: "💀",
    Verdict.UNKNOWN: "❓",
}


@app.command()
def scan(
    repo: str = typer.Argument(..., help="GitHub repo URL or owner/repo slug"),
    token: str = typer.Option(None, "--token", "-t", envvar="GITHUB_TOKEN"),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal | json"),
    feedback: bool = typer.Option(
        False, "--feedback", "-f", help="Prompt for feedback after scan"
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Bypass cache and force fresh fetch"
    ),
    ttl: int = typer.Option(6, "--ttl", help="Cache TTL in hours (default: 6)"),
    no_whitelist: bool = typer.Option(
        False, "--no-whitelist", help="Disable whitelist capping (audit mode)"
    ),
) -> None:
    """Scan a single GitHub repository."""
    from legitifier_pkg.cache import FetchCache  # noqa: F401

    llm_client = client_from_env()
    silent = output == "json"
    pipeline = Pipeline(
        github_token=token or os.getenv("GITHUB_TOKEN"),
        llm_client=llm_client,
        silent=silent,
    )
    if no_cache:
        pipeline._github._cache.delete(repo)
    report, scan_id = pipeline.run(repo, no_whitelist=no_whitelist)

    if output == "json":
        typer.echo(report.model_dump_json(indent=2))
    else:
        terminal_report.render(report)

    if feedback:
        _collect_feedback(scan_id, report.verdict)

    raise typer.Exit(code=0 if report.risk_score < 50 else 1)


@app.command()
def search(
    preset: str = typer.Option(
        None, "--preset", "-p", help="Use a built-in search preset"
    ),
    topic: str = typer.Option(
        None, "--topic", help="GitHub topic filter (e.g. llm, gpt)"
    ),
    language: str = typer.Option(None, "--language", "-l", help="Programming language"),
    stars: str = typer.Option(
        None, "--stars", help='Star count filter (e.g. ">500", "100..1000")'
    ),
    forks: str = typer.Option(None, "--forks", help='Fork count filter (e.g. "<20")'),
    created: str = typer.Option(
        None, "--created", help='Creation date filter (e.g. ">2024-01-01")'
    ),
    pushed: str = typer.Option(
        None, "--pushed", help='Last push date filter (e.g. "<2024-06-01")'
    ),
    extra: str = typer.Option(
        None, "--query", "-q", help="Raw GitHub search query string"
    ),
    source: str = typer.Option(
        "search", "--source", "-s", help="Source: search | trending | starscout | file"
    ),
    since: str = typer.Option(
        "daily",
        "--since",
        help="Trending period: daily | weekly | monthly (with --source trending)",
    ),
    input_file: str = typer.Option(
        None, "--input", "-i", help="Input file path (with --source file)"
    ),
    limit: int = typer.Option(20, "--limit", "-n", help="Max repos to scan"),
    token: str = typer.Option(None, "--token", "-t", envvar="GITHUB_TOKEN"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass GitHub data cache"),
    rescan: bool = typer.Option(
        False, "--rescan", help="Rescan repos already in history"
    ),
    reset: bool = typer.Option(
        False, "--reset", help="Reset search position to beginning"
    ),
    delay: float = typer.Option(
        4.0, "--delay", "-d", help="Seconds between scans (default: 4.0s with token)"
    ),
    list_presets: bool = typer.Option(
        False, "--list-presets", help="Show available presets and exit"
    ),
) -> None:
    """Search GitHub and scan matching repositories."""
    import time

    from legitifier_pkg.search import (
        build_query,
        file_repos,
        load_presets,
        search_repos,
        starscout_repos,
        trending_repos,
    )

    presets = load_presets()

    if list_presets:
        console.print("\n[bold]Available presets:[/]\n")
        for name, data in presets.items():
            console.print(f"  [cyan]{name}[/] — {data['description']}")
            console.print(f"    [dim]{data['query']}[/]\n")
        raise typer.Exit()

    gh_token = token or os.getenv("GITHUB_TOKEN")
    if delay == 4.0 and not gh_token:
        console.print(
            "[yellow]Warning: no GITHUB_TOKEN — batch scanning very slow (60 req/hour).[/]"
        )
        delay = 520.0

    llm_client = client_from_env()
    pipeline = Pipeline(github_token=gh_token, llm_client=llm_client, silent=True)
    store = FeedbackStore()
    new_offset = 0
    query = ""

    if source == "trending":
        repo_iter = trending_repos(
            language=language or "", since=since, limit=min(limit * 5, 100)
        )
        console.print(
            f"\n[dim]Source:[/] GitHub Trending  [dim]Since:[/] {since}"
            + (f"  [dim]Language:[/] {language}" if language else "")
        )
    elif source == "starscout":
        console.print(
            "\n[dim]Source:[/] CMU StarScout dataset (ICSE 2026) — downloading..."
        )
        repo_iter = starscout_repos(limit=min(limit * 5, 1000))
    elif source == "file":
        if not input_file:
            console.print("[red]--input required with --source file[/]")
            raise typer.Exit(1)
        console.print(f"\n[dim]Source:[/] File — {input_file}")
        repo_iter = file_repos(input_file, limit=min(limit * 5, 1000))
    else:
        if preset:
            if preset not in presets:
                console.print(f"[red]Unknown preset '{preset}'. Use --list-presets.[/]")
                raise typer.Exit(1)
            query = presets[preset]["query"]
            console.print(f"Using preset [cyan]{preset}[/]: [dim]{query}[/]")
        else:
            query = build_query(
                topic=topic,
                language=language,
                stars=stars,
                forks=forks,
                created=created,
                pushed=pushed,
                extra=extra,
            )
        if not query.strip():
            console.print(
                "[red]No criteria. Use --source trending, --preset, --topic, --stars, or --query.[/]"
            )
            raise typer.Exit(1)
        if limit > 1000:
            console.print("[yellow]GitHub Search API capped at 1000 results.[/]")
            limit = 1000
        if reset:
            store.reset_search_offset(query)
            console.print("[dim]Search position reset.[/]")
        offset = store.get_search_offset(query)
        new_offset = offset
        if offset:
            console.print(f"[dim]Resuming from position {offset}[/]")
        console.print(f"\n[dim]Searching:[/] {query}")
        repo_iter = search_repos(
            query, gh_token, min(limit * 5, 1000), start_offset=offset
        )

    console.print(f"[dim]Limit:[/] {limit} new scans  [dim]Delay:[/] {delay:.1f}s\n")

    counts = {v: 0 for v in Verdict}
    scanned = 0
    errors = 0

    for repo_url, global_index in repo_iter:
        if repo_url.startswith("__rate_limit__:"):
            wait = int(repo_url.split(":")[1])
            console.print(f"[yellow]Rate limited — waiting {wait}s...[/]")
            time.sleep(wait)
            continue
        if repo_url.startswith("__error__:"):
            console.print(f"[red]Search error: {repo_url.split(':', 1)[1]}[/]")
            break

        new_offset = global_index + 1
        slug = repo_url.split("github.com/")[-1]
        if no_cache:
            pipeline._github._cache.delete(repo_url)

        # Skip repos already scanned with current version and same repo state
        if not no_cache and not rescan:
            from legitifier_pkg import __version__

            if store.get_recent_scan(
                repo_url, max_age_seconds=3600, current_version=__version__
            ):
                continue

        try:
            report, _ = pipeline.run(repo_url)
            verdict = report.verdict
            color = _VERDICT_COLOR[verdict]
            icon = _VERDICT_ICON[verdict]
            trust = trust_score(report.risk_score)
            triggered = len([r for r in report.results if r.triggered])
            console.print(
                f"[{color}]{icon} {verdict.value:12}[/] "
                f"Trust [bold]{trust:3.0f}[/]  "
                f"[dim]{triggered} signals  {report.scan_duration_seconds:.1f}s[/]  "
                f"{slug}"
            )
            counts[verdict] += 1
            scanned += 1
        except Exception as e:
            console.print(f"[red]ERROR[/]  {slug}: {e}")
            errors += 1

        if scanned >= limit:
            break
        time.sleep(delay)

    if query:
        store.set_search_offset(query, new_offset)

    console.print(f"\n{'─' * 60}")
    console.print(
        f"[bold]{scanned} new scans[/]  •  "
        f"[red]{counts[Verdict.SCAM]} scam[/]  "
        f"[orange3]{counts[Verdict.LIKELY_SCAM]} likely_scam[/]  "
        f"[yellow]{counts[Verdict.SUSPICIOUS]} suspicious[/]  "
        f"[green]{counts[Verdict.CLEAN]} clean[/]  "
        f"[dim]{counts[Verdict.UNKNOWN]} unknown[/]"
        + (f"  [red]{errors} errors[/]" if errors else "")
    )
    console.print("[dim]Results saved — use 'legitifier history' to review[/]")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
    verdict: str = typer.Option(
        None,
        "--verdict",
        "-v",
        help="Filter by verdict: CLEAN, SUSPICIOUS, LIKELY_SCAM, SCAM, UNKNOWN",
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal | json"),
) -> None:
    """Show recent scan history."""
    from datetime import datetime

    from legitifier_pkg.feedback.store import FeedbackStore
    from legitifier_pkg.reports.terminal import trust_score

    store = FeedbackStore()
    scans = store.recent_scans(limit=limit, verdict_filter=verdict)

    if not scans:
        console.print("[dim]No scans found.[/]")
        raise typer.Exit()

    if output == "json":
        import json

        typer.echo(json.dumps(scans, indent=2, default=str))
        raise typer.Exit()

    _COLORS = {
        "CLEAN": "green",
        "SUSPICIOUS": "yellow",
        "LIKELY_SCAM": "orange3",
        "SCAM": "red",
        "UNKNOWN": "dim",
    }
    _ICONS = {
        "CLEAN": "✅",
        "SUSPICIOUS": "⚠️ ",
        "LIKELY_SCAM": "🚨",
        "SCAM": "💀",
        "UNKNOWN": "❓",
    }

    from rich import box
    from rich.table import Table

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Verdict", width=14)
    table.add_column("Trust", justify="right", width=6)
    table.add_column("Repository")
    table.add_column("Scanned", width=14)

    now = datetime.now(UTC)

    for scan in scans:
        v = scan["verdict"]
        color = _COLORS.get(v, "white")
        icon = _ICONS.get(v, "?")
        trust = f"{trust_score(scan['risk_score']):.0f}"
        slug = scan["repo_url"].replace("https://", "").replace("github.com/", "")

        # Human-readable relative time
        try:
            scanned_at = datetime.fromisoformat(scan["scanned_at"])
            if scanned_at.tzinfo is None:
                scanned_at = scanned_at.replace(tzinfo=UTC)
            delta = now - scanned_at
            secs = int(delta.total_seconds())
            if secs < 60:
                when = f"{secs}s ago"
            elif secs < 3600:
                when = f"{secs // 60}m ago"
            elif secs < 86400:
                when = f"{secs // 3600}h ago"
            else:
                when = f"{secs // 86400}d ago"
        except Exception:
            when = scan["scanned_at"][:10]

        table.add_row(
            f"[{color}]{icon} {v}[/]",
            f"[bold]{trust}[/]",
            f"[dim]{slug}[/]",
            f"[dim]{when}[/]",
        )

    console.print(table)
    console.print(f"[dim]{len(scans)} scan(s) shown[/]")


@app.command()
def cache_clear(
    all: bool = typer.Option(False, "--all", help="Clear all cached entries"),
) -> None:
    """Clear expired or all cache entries."""
    from legitifier_pkg.cache import FetchCache

    c = FetchCache()
    if all:
        c._path.unlink(missing_ok=True)
        typer.echo("Cache cleared.")
    else:
        n = c.purge_expired()
        typer.echo(f"Removed {n} expired entries.")


@app.command()
def export(
    output: Path = typer.Argument(Path("dataset.jsonl"), help="Output JSONL file"),
    anonymize: bool = typer.Option(
        False,
        "--anonymize",
        help="Replace GitHub logins with stable hashes (publish-safe)",
    ),
) -> None:
    """Export annotated scans as a JSONL training dataset."""
    from legitifier_pkg.feedback.export import export_jsonl

    count = export_jsonl(output, anonymize=anonymize)
    suffix = " (anonymized)" if anonymize else ""
    typer.echo(f"Exported {count} annotated records to {output}{suffix}")


@app.command()
def forget(
    login: str = typer.Argument(
        ..., help="GitHub login to remove from all local databases"
    ),
    deep: bool = typer.Option(
        False, "--deep", help="Also scrub from nested report data"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Erase all traces of a GitHub user from local storage (GDPR Article 17)."""
    if not yes:
        confirmed = Confirm.ask(
            f"Permanently erase all data about '{login}'? This cannot be undone."
        )
        if not confirmed:
            raise typer.Exit(code=1)
    store = FeedbackStore()
    counts = store.forget_login(login)
    if deep:
        deep_counts = store.forget_login_deep(login)
        counts.update(deep_counts)
    console.print(
        f"✅ Erased: {counts['scans']} scans, {counts['feedback']} feedbacks, "
        f"{counts['reputation']} reputation entries, "
        f"{counts['cache']} cache entries"
        + (f", {counts.get('reports_scrubbed', 0)} reports scrubbed" if deep else "")
        + f" for '{login}'."
    )


def _collect_feedback(scan_id: int, auto_verdict: Verdict) -> None:
    typer.echo(f"\nAuto verdict: {auto_verdict.value}")
    if not Confirm.ask("Is this verdict correct?", default=True):
        choice = Prompt.ask(
            "Correct verdict",
            choices=[v.value for v in Verdict],
            default=auto_verdict.value,
        )
        user_verdict = Verdict(choice)
    else:
        user_verdict = auto_verdict

    confidence = Confidence(
        Prompt.ask(
            "Confidence", choices=["certain", "probable", "unsure"], default="probable"
        )
    )
    note = Prompt.ask("Note (optional, press Enter to skip)", default="") or None

    store = FeedbackStore()
    store.save_feedback(scan_id, user_verdict, confidence, note)
    typer.echo("Feedback saved locally.")


if __name__ == "__main__":
    app()
