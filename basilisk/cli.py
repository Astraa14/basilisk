"""Basilisk CLI - installable terminal scanner with a simple Rich UI."""

from __future__ import annotations

import logging
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from basilisk.core import Basilisk

logging.getLogger("basilisk").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Avoid cp1252 crashes on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="basilisk",
    help="Basilisk - web vulnerability scanner for live apps.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(legacy_windows=False)

SEVERITY_STYLE = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim",
}


def _banner(url: str) -> None:
    console.print(
        Panel(
            Text.from_markup(
                f"[bold]BASILISK[/bold]  |  scanning [cyan]{url}[/cyan]\n"
                "[dim]crawl -> passive audit -> active fuzz[/dim]"
            ),
            border_style="green",
            padding=(1, 2),
        )
    )


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        console.print(
            Panel(
                "[green]No issues flagged.[/green]",
                title="Results",
                border_style="green",
            )
        )
        return

    table = Table(title="Findings", show_lines=False, expand=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Issue")
    table.add_column("Target", overflow="fold")

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "Info"), 9))

    for idx, issue in enumerate(ranked, 1):
        sev = issue.get("severity", "Info")
        style = SEVERITY_STYLE.get(sev, "white")
        table.add_row(
            str(idx),
            Text(sev, style=style),
            issue.get("vulnerability", "Unknown"),
            issue.get("target", ""),
        )

    console.print(table)
    console.print()
    for idx, issue in enumerate(ranked, 1):
        console.print(f"  [dim]{idx}.[/dim] {issue.get('description', '')}")


def _print_summary(report: dict) -> None:
    findings = report.get("findings", [])
    high = sum(1 for f in findings if f.get("severity") in ("High", "Critical"))
    status = (
        f"[bold red]{high} high-severity issue(s)[/bold red]"
        if high
        else "[green]no high-severity issues[/green]"
    )
    console.print(
        Panel(
            f"Pages: [cyan]{report.get('pages_scanned', 0)}[/cyan]  |  "
            f"Forms: [cyan]{report.get('forms_found', 0)}[/cyan]  |  "
            f"Findings: [cyan]{len(findings)}[/cyan]  |  {status}",
            title="Summary",
            border_style="red" if high else "green",
        )
    )


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target base URL (e.g. https://example.com)"),
    max_pages: int = typer.Option(15, "--max-pages", "-n", help="Crawl page limit"),
    no_active: bool = typer.Option(
        False, "--no-active", help="Skip active form fuzzing (passive only)"
    ),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
):
    """Full site scan: crawl, passive headers/secrets, then active SQLi/XSS fuzz."""
    _banner(url)
    scanner = Basilisk(target_url=url, timeout=timeout)

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_progress(msg: str) -> None:
            progress.update(task, description=msg[:80])

        report = scanner.scan(
            max_pages=max_pages,
            active=not no_active,
            on_progress=on_progress,
        )

    console.print()
    _print_findings(report.get("findings", []))
    _print_summary(report)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


@app.command("login")
def login_scan(
    url: str = typer.Argument(..., help="Target base URL"),
    endpoint: str = typer.Option("/login", "--endpoint", "-e", help="Login path"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
):
    """Probe a login endpoint for SQL injection."""
    _banner(f"{url}{endpoint}")
    scanner = Basilisk(target_url=url, timeout=timeout)

    with console.status("[green]Probing login endpoint...[/green]", spinner="dots"):
        report = scanner.scan_login(login_endpoint=endpoint)

    findings = report.get("findings", [])
    if report.get("exploits_found") and not findings:
        for exploit in report["exploits_found"]:
            findings.append(
                {
                    "vulnerability": "Potential SQL Injection (Login)",
                    "severity": "High",
                    "description": f"{exploit['reason']} - payload: {exploit['payload']}",
                    "target": report["target"],
                }
            )

    console.print()
    _print_findings(findings)
    console.print(
        Panel(
            f"Target: [cyan]{report['target']}[/cyan]  |  "
            f"{'[bold red]VULNERABLE[/bold red]' if report.get('vulnerable') else '[green]safe responses[/green]'}",
            title="Login Scan",
            border_style="red" if report.get("vulnerable") else "green",
        )
    )

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
