"""Basilisk CLI - installable terminal scanner with a simple Rich UI."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import typer
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.console import Group

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

def _version_callback(value: bool) -> None:
    if value:
        from basilisk import __version__
        console.print(f"Basilisk v{__version__}")
        raise typer.Exit()


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

DASHBOARD_URL = "https://basilisk-scan.vercel.app"


def _resolve_llm(
    force_llm: bool,
    no_llm: bool,
    api_key: str | None,
) -> tuple[bool, str | None]:
    load_llm_env()
    if no_llm:
        return False, api_key
    if force_llm:
        return True, api_key
    if llm_configured(api_key):
        return True, api_key
    return False, api_key


def _draw_basilisk_logo() -> Group:
    art = pyfiglet.figlet_format("BASILISK", font="block")
    logo = Text(art, style="bold green", justify="center")
    subtitle = Text("Advanced Web Vulnerability Scanner & Reconnaissance Engine", style="dim italic", justify="center")
    spacer = Text("", justify="center")
    return Group(logo, subtitle, spacer)


def _banner(url: str, mode: str = "static") -> None:
    if mode == "llm":
        pipeline = "Generator(LLM) -> Target -> Judge(LLM)"
    else:
        pipeline = "Static templates -> Target -> Heuristic Judge"
    console.print(_draw_basilisk_logo())
    console.print(
        Panel(
            Text.from_markup(
                f"scanning [cyan]{url}[/cyan]\n"
                f"[dim]recon -> {pipeline}[/dim]",
                justify="center",
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
        desc = issue.get('description', '')
        payload = issue.get('payload', '')
        line = f"  [dim]{idx}.[/dim] {desc}"
        if payload:
            line += f"\n       [dim]payload:[/dim] [italic]{payload[:80]}[/italic]"
        console.print(line)


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


def _export_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]\u2713[/green] Results saved to [cyan]{path}[/cyan]")


def _export_html(report: dict, path: Path) -> None:
    findings = report.get("findings", [])
    rows = ""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "Info"), 9))
    for f in ranked:
        sev = f.get("severity", "Info")
        color = {"Critical": "#dc2626", "High": "#ef4444", "Medium": "#eab308", "Low": "#06b6d4", "Info": "#6b7280"}.get(sev, "#6b7280")
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{sev}</span></td>
          <td>{f.get('vulnerability', '')}</td>
          <td style="word-break:break-all">{f.get('target', '')}</td>
          <td>{f.get('description', '')}</td>
        </tr>"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Basilisk Scan Report</title>
<style>
body {{ font-family:-apple-system,sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem }}
h1 {{ color:#22c55e }} .meta {{ color:#94a3b8; margin:1rem 0 }}
table {{ width:100%; border-collapse:collapse; margin-top:1rem }}
th,td {{ padding:.75rem 1rem; text-align:left; border-bottom:1px solid #334155 }}
th {{ color:#94a3b8; font-size:.875rem }}
</style></head>
<body>
<h1>Basilisk Scan Report</h1>
<div class="meta">
  <strong>Target:</strong> {report.get('target', '')}<br>
  <strong>Mode:</strong> {report.get('mode', 'static')} |
  <strong>Pages:</strong> {report.get('pages_scanned', 0)} |
  <strong>Forms:</strong> {report.get('forms_found', 0)} |
  <strong>Findings:</strong> {len(findings)} |
  <strong>Vulnerable:</strong> {report.get('vulnerable', False)}
</div>
<table><thead><tr><th>Severity</th><th>Issue</th><th>Target</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="color:#64748b;margin-top:2rem;font-size:.875rem">Generated by Basilisk on {datetime.utcnow().isoformat()}</p>
</body></html>"""
    path.write_text(html, encoding="utf-8")
    console.print(f"[green]\u2713[/green] HTML report saved to [cyan]{path}[/cyan]")


def _parse_cookie(value: str | None) -> dict | None:
    if not value:
        return None
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies or None


def _parse_headers(values: list[str] | None) -> dict | None:
    if not values:
        return None
    headers: dict[str, str] = {}
    for item in values:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers or None


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target base URL (e.g. https://example.com)"),
    max_pages: int = typer.Option(15, "--max-pages", "-n", help="Crawl page limit"),
    no_active: bool = typer.Option(False, "--no-active", help="Skip active form fuzzing (passive only)"),
    no_url_fuzz: bool = typer.Option(False, "--no-url-fuzz", help="Skip URL parameter fuzzing"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
    delay: float = typer.Option(0.0, "--delay", "-w", help="Delay seconds between requests"),
    retries: int = typer.Option(1, "--retries", "-r", help="Max HTTP retries per request"),
    use_llm: bool = typer.Option(False, "--llm", help="Force LLM Generator + Judge on"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Force static-only mode (ignore API key)"),
    api_key: str | None = typer.Option(None, "--api-key", help="LLM API key (prefer .env: BASILISK_LLM_API_KEY)"),
    dataset: str | None = typer.Option(None, "--dataset", "-d", help="Optional custom JSON payload dataset path"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save results to file (.json or .html)"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout"),
    cookie: str | None = typer.Option(None, "--cookie", "-c", help="Request cookies (e.g. 'session=abc; token=xyz')"),
    header: list[str] = typer.Option([], "--header", "-H", help="Extra request headers (e.g. 'X-Custom: value')"),
):
    """Full site scan: recon, passive audit, then Attack Engine fuzzing."""
    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"

    extra_headers = _parse_headers(header) if header else None
    cookies = _parse_cookie(cookie) if cookie else None

    if not json_output:
        _banner(url, mode=mode)

    try:
        scanner = Basilisk(
            target_url=url,
            timeout=timeout,
            use_llm=enabled,
            custom_dataset=dataset,
            api_key=key,
            delay=delay,
            max_retries=retries,
            extra_headers=extra_headers,
            cookies=cookies,
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
                fuzz_url_params=not no_url_fuzz,
                on_progress=on_progress,
            )
        except LLMError as exc:
            console.print(f"[bold red]LLM error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

    if json_output:
        console.print_json(json.dumps(report, default=str))
        return

    console.print()
    _print_findings(report.get("findings", []))
    _print_summary(report)

    if output:
        out_path = Path(output)
        if out_path.suffix == ".html":
            _export_html(report, out_path)
        else:
            _export_json(report, out_path)

    _try_upload(report)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


@app.command("login")
def login_scan(
    url: str = typer.Argument(..., help="Target base URL"),
    endpoint: str = typer.Option("/login", "--endpoint", "-e", help="Login path"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout seconds"),
    delay: float = typer.Option(0.0, "--delay", "-w", help="Delay seconds between requests"),
    retries: int = typer.Option(1, "--retries", "-r", help="Max HTTP retries per request"),
    use_llm: bool = typer.Option(False, "--llm", help="Force LLM Generator + Judge on"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Force static-only mode (ignore API key)"),
    api_key: str | None = typer.Option(None, "--api-key", help="LLM API key (prefer .env: BASILISK_LLM_API_KEY)"),
    dataset: str | None = typer.Option(None, "--dataset", "-d", help="Optional custom JSON payload dataset path"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save results to file (.json or .html)"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout"),
    cookie: str | None = typer.Option(None, "--cookie", "-c", help="Request cookies (e.g. 'session=abc; token=xyz')"),
    header: list[str] = typer.Option([], "--header", "-H", help="Extra request headers (e.g. 'X-Custom: value')"),
):
    """Probe a login endpoint for SQL injection via the Attack Engine."""
    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"

    extra_headers = _parse_headers(header) if header else None
    cookies = _parse_cookie(cookie) if cookie else None

    if not json_output:
        _banner(f"{url}{endpoint}", mode=mode)

    try:
        scanner = Basilisk(
            target_url=url,
            timeout=timeout,
            use_llm=enabled,
            custom_dataset=dataset,
            api_key=key,
            delay=delay,
            max_retries=retries,
            extra_headers=extra_headers,
            cookies=cookies,
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

    if json_output:
        console.print_json(json.dumps(report, default=str))
        return

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

    if output:
        out_path = Path(output)
        if out_path.suffix == ".html":
            _export_html(report, out_path)
        else:
            _export_json(report, out_path)

    _try_upload(report)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


@app.command("auth")
def auth_login() -> None:
    """Log in to Basilisk dashboard (opens browser for authentication)."""
    console.print(_draw_basilisk_logo())
    console.print(
        Panel(
            Text.from_markup(
                "Dashboard Authentication\n"
                "[dim]This will open your browser to complete sign-in.[/dim]",
                justify="center",
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
    if "--version" in sys.argv or "-V" in sys.argv:
        _version_callback(True)
    app()


if __name__ == "__main__":
    main()
