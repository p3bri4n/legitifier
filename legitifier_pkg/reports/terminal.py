from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from legitifier_pkg.core.models import ScanReport, Verdict

_VERDICT_COLOR = {
    Verdict.CLEAN: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.LIKELY_SCAM: "orange3",
    Verdict.SCAM: "red",
    Verdict.UNKNOWN: "dim",
}

_VERDICT_ICON = {
    Verdict.CLEAN: "✅",
    Verdict.SUSPICIOUS: "⚠️",
    Verdict.LIKELY_SCAM: "🚨",
    Verdict.SCAM: "💀",
    Verdict.UNKNOWN: "❓",
}

console = Console()


def trust_score(risk_score: float) -> float:
    return round(100.0 - risk_score, 1)


def render(report: ScanReport) -> None:
    color = _VERDICT_COLOR[report.verdict]
    icon = _VERDICT_ICON[report.verdict]
    duration = f"{report.scan_duration_seconds:.1f}s"

    if report.verdict == Verdict.UNKNOWN:
        console.print(
            Panel(
                f"{icon} [bold {color}]UNKNOWN[/] — Repository not found or inaccessible\n"
                f"[dim]{report.repo_url}[/]  [dim]({duration})[/]",
                title="[bold]legitifier[/]",
                border_style=color,
            )
        )
        if report.errors:
            console.print(f"[yellow]Error:[/] {report.errors[0]}")
        return

    trust = trust_score(report.risk_score)
    triggered = [r for r in report.results if r.triggered]
    total = len(report.results)

    console.print(
        Panel(
            f"{icon} [bold {color}]{report.verdict.value}[/] — Trust: [bold]{trust:.0f}/100[/]  "
            f"[dim]({len(triggered)}/{total} signals • {duration} • v{report.scanner_version})[/]\n"
            f"[dim]{report.repo_url}[/]",
            title="[bold]legitifier[/]",
            border_style=color,
        )
    )

    if triggered:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("Heuristic", style="dim")
        table.add_column("Risk", justify="right")
        table.add_column("Severity")
        table.add_column("Evidence")

        for r in sorted(triggered, key=lambda x: x.score, reverse=True):
            sev_color = {
                "low": "green",
                "medium": "yellow",
                "high": "orange3",
                "critical": "red",
            }
            c = sev_color.get(r.severity.value, "white")
            table.add_row(
                f"🚩 {r.heuristic_id}",
                f"[{c}]{r.score:.0f}[/]",
                f"[{c}]{r.severity.value}[/]",
                r.evidence.strip(),
            )
        console.print(table)
    else:
        console.print("[dim]  No signals triggered.[/]")

    if report.errors:
        console.print(f"[yellow]Warnings:[/] {', '.join(report.errors)}")
