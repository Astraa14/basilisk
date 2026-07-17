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
from basilisk.llm import LLMError, load_llm_env, llm_configured
from basilisk import auth as _auth_module
from basilisk.config import (
    clear_config,
    config_exists,
    load_backend_api_key,
    load_backend_username,
    save_backend_api_key,
)
from basilisk.reporter import send_report_to_backend

logging.getLogger("basilisk").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="basilisk",
    help="Basilisk - web vulnerability scanner (recon + attack engine + judge).",
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

# Update this URL after production deployment (Task 4.5)
DASHBOARD_URL = "https://basilisk-livid.vercel.app"


def _resolve_llm(
    force_llm: bool,
    no_llm: bool,
    api_key: str | None,
) -> tuple[bool, str | None]:
    """LLM is on when a key exists, unless --no-llm. --llm forces it on."""
    load_llm_env()
    if no_llm:
        return False, api_key
    if force_llm:
        return True, api_key
    # Auto-enable full Generator+Judge pipeline when a key is available
    if llm_configured(api_key):
        return True, api_key
    return False, api_key


def _banner(url: str, mode: str = "static") -> None:
    if mode == "llm":
        pipeline = "Generator(LLM) -> Target -> Judge(LLM)"
    else:
        pipeline = "Static templates -> Target -> Heuristic Judge"
    console.print(
        Panel(
            Text.from_markup(
                f"[bold]BASILISK[/bold]  |  scanning [cyan]{url}[/cyan]\n"
                f"[dim]recon -> {pipeline}[/dim]"
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
    mode = report.get("mode", "static")
    console.print(
        Panel(
            f"Mode: [cyan]{mode}[/cyan]  |  "
            f"Pages: [cyan]{report.get('pages_scanned', 0)}[/cyan]  |  "
            f"Forms: [cyan]{report.get('forms_found', 0)}[/cyan]  |  "
            f"Findings: [cyan]{len(findings)}[/cyan]  |  {status}",
            title="Summary",
            border_style="red" if high else "green",
        )
    )


def _try_upload(report: dict) -> None:
    """Upload the scan report to the dashboard if an API key is configured."""
    api_key = load_backend_api_key()
    if not api_key:
        console.print(
            "[dim]Tip: Run [bold]basilisk auth[/bold] to save scans to your dashboard.[/dim]"
        )
        return
    with console.status("[dim]Uploading to dashboard...[/dim]", spinner="dots"):
        scan_id = send_report_to_backend(report, api_key)
    if scan_id:
        console.print(
            f"[green]\u2713[/green] View at: [cyan]{DASHBOARD_URL}/scans/{scan_id}[/cyan]"
        )
    else:
        console.print("[dim]Upload skipped \u2014 results saved locally only.[/dim]")


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target base URL (e.g. https://example.com)"),
    max_pages: int = typer.Option(15, "--max-pages", "-n", help="Crawl page limit"),
    no_active: bool = typer.Option(
        False, "--no-active", help="Skip active form fuzzing (passive only)"
    ),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
    use_llm: bool = typer.Option(
        False, "--llm", help="Force LLM Generator + Judge on"
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Force static-only mode (ignore API key)"
    ),
    api_key: str | None = typer.Option(
        None, "--api-key", help="LLM API key (prefer .env: BASILISK_LLM_API_KEY)"
    ),
    dataset: str | None = typer.Option(
        None, "--dataset", "-d", help="Optional custom JSON payload dataset path"
    ),
):
    """Full site scan: recon, passive audit, then Attack Engine fuzzing."""
    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"
    _banner(url, mode=mode)

    try:
        scanner = Basilisk(
            target_url=url,
            timeout=timeout,
            use_llm=enabled,
            custom_dataset=dataset,
            api_key=key,
        )
    except LLMError as exc:
        console.print(f"[bold red]LLM config error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_progress(msg: str) -> None:
            progress.update(task, description=msg[:80])

        try:
            report = scanner.scan(
                max_pages=max_pages,
                active=not no_active,
                on_progress=on_progress,
            )
        except LLMError as exc:
            console.print(f"[bold red]LLM error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

    console.print()
    _print_findings(report.get("findings", []))
    _print_summary(report)
    _try_upload(report)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


@app.command("login")
def login_scan(
    url: str = typer.Argument(..., help="Target base URL"),
    endpoint: str = typer.Option("/login", "--endpoint", "-e", help="Login path"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
    use_llm: bool = typer.Option(
        False, "--llm", help="Force LLM Generator + Judge on"
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Force static-only mode (ignore API key)"
    ),
    api_key: str | None = typer.Option(
        None, "--api-key", help="LLM API key (prefer .env: BASILISK_LLM_API_KEY)"
    ),
    dataset: str | None = typer.Option(
        None, "--dataset", "-d", help="Optional custom JSON payload dataset path"
    ),
):
    """Probe a login endpoint for SQL injection via the Attack Engine."""
    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"
    _banner(f"{url}{endpoint}", mode=mode)

    try:
        scanner = Basilisk(
            target_url=url,
            timeout=timeout,
            use_llm=enabled,
            custom_dataset=dataset,
            api_key=key,
        )
    except LLMError as exc:
        console.print(f"[bold red]LLM config error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    with console.status("[green]Probing login endpoint...[/green]", spinner="dots"):
        try:
            report = scanner.scan_login(login_endpoint=endpoint)
        except LLMError as exc:
            console.print(f"[bold red]LLM error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

    findings = report.get("findings", [])
    console.print()
    _print_findings(findings)
    console.print(
        Panel(
            f"Mode: [cyan]{report.get('mode', mode)}[/cyan]  |  "
            f"Target: [cyan]{report['target']}[/cyan]  |  "
            f"{'[bold red]VULNERABLE[/bold red]' if report.get('vulnerable') else '[green]safe responses[/green]'}",
            title="Login Scan",
            border_style="red" if report.get("vulnerable") else "green",
        )
    )
    _try_upload(report)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


@app.command("auth")
def auth_login() -> None:
    """Log in to Basilisk dashboard (opens browser for authentication)."""
    console.print(
        Panel(
            Text.from_markup(
                "[bold]BASILISK[/bold]  |  Dashboard Authentication\n"
                "[dim]This will open your browser to complete sign-in.[/dim]"
            ),
            border_style="cyan",
            padding=(1, 2),
        )
    )

    try:
        data = _auth_module.request_device_code()
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2)

    user_code: str = data.get("user_code", "")
    verification_uri: str = data.get("verification_uri", "")
    device_code: str = data.get("device_code", "")

    console.print()
    console.print(f"  [dim]Open this URL in your browser:[/dim]")
    console.print(f"  [bold cyan]{verification_uri}[/bold cyan]")
    console.print()
    console.print(f"  [dim]Your one-time code:[/dim]")
    console.print(f"  [bold white on blue]  {user_code}  [/bold white on blue]")
    console.print()

    _auth_module.open_auth_browser(verification_uri)

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Waiting for browser confirmation...", total=None)
        result = _auth_module.poll_for_backend_key(device_code)

    if not result or result[0] is None:
        console.print("[bold red]Authentication timed out.[/bold red] Please try again.")
        raise typer.Exit(code=2)

    key, username = result
    save_backend_api_key(key, username or "")

    console.print(
        f"[green]\u2713[/green] Logged in"
        + (f" as [bold]{username}[/bold]" if username else "")
    )
    console.print(
        f"[dim]Next: [bold]basilisk scan https://example.com[/bold][/dim]"
    )


@app.command("logout")
def logout() -> None:
    """Remove saved API key and log out from the dashboard."""
    if config_exists():
        username = load_backend_username()
        clear_config()
        msg = f"Logged out" + (f" ({username})" if username else "")
        console.print(f"[green]\u2713[/green] {msg}")
    else:
        console.print("[dim]Not logged in — nothing to do.[/dim]")


def main() -> None:
    load_llm_env()
    app()


if __name__ == "__main__":
    main()
