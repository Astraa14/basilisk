"""Basilisk CLI — security vulnerability scanner with local & Vercel dashboard support."""

from __future__ import annotations

import json
import logging
import os
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
from basilisk.models import ScanConfig
from basilisk.reporter import save_json, save_html, send_report_to_backend
from basilisk.web_server import EphemeralDashboardServer
from basilisk.config import load_backend_api_key, load_backend_username, clear_config

logging.getLogger("basilisk").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

DASHBOARD_URL = os.getenv("BASILISK_FRONTEND_URL", "https://basilisk-livid.vercel.app")

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
    help="Basilisk — web vulnerability scanner.",
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
    subtitle = Text(
        "AI-Powered Web Vulnerability Scanner",
        style="dim italic",
        justify="center",
    )
    spacer = Text("", justify="center")
    return Group(logo, subtitle, spacer)


def _banner(url: str, mode: str = "static", server: EphemeralDashboardServer | None = None) -> None:
    if mode == "llm":
        pipeline = "Generator(LLM) -> Target -> Judge(LLM)"
    else:
        pipeline = "Static templates -> Target -> Heuristic Judge"
    console.print(_draw_basilisk_logo())
    
    user = load_backend_username()
    auth_str = f"[green]Logged in as {user}[/green]" if user else "[dim]Not logged in (results local)[/dim]"

    panel_content = (
        f"scanning [cyan]{url}[/cyan]\n"
        f"[dim]recon -> {pipeline}[/dim]\n"
        f"{auth_str}"
    )
    
    if server:
        panel_content += (
            f"\n\n[bold green]Live Session Local Dashboard Active:[/bold green]\n"
            f"  [dim]URL:[/dim] [bold cyan]{server.url}[/bold cyan]\n"
            f"  [dim]Session Passcode:[/dim] [bold white on blue]  {server.passcode}  [/bold white on blue]\n"
            f"  [dim](Local session self-destructs when CLI process exits)[/dim]"
        )

    console.print(
        Panel(
            Text.from_markup(panel_content, justify="center"),
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
        desc = issue.get("description", "")
        payload = issue.get("payload", "")
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


def _export(report: dict, output: str) -> None:
    out_path = Path(output)
    if out_path.suffix.lower() == ".html":
        save_html(report, out_path)
        console.print(f"[green]\u2713[/green] HTML report saved to [cyan]{out_path}[/cyan]")
    else:
        save_json(report, out_path)
        console.print(f"[green]\u2713[/green] Results saved to [cyan]{out_path}[/cyan]")


def _try_upload(report: dict) -> None:
    api_key = load_backend_api_key()
    if not api_key:
        return
    with console.status("[dim]Uploading report to Vercel dashboard...[/dim]", spinner="dots"):
        scan_id = send_report_to_backend(report, api_key)
    if scan_id:
        console.print(f"[green]\u2713[/green] Report uploaded to dashboard: [bold cyan]{DASHBOARD_URL}/scans/{scan_id}[/bold cyan]")
    else:
        console.print("[dim]Could not sync to cloud dashboard (saved locally).[/dim]")


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


def _build_config(
    timeout: float,
    delay: float,
    retries: int,
    proxy: str | None,
    verify_tls: bool,
    max_redirects: int,
    pool_size: int,
    auth_bearer: str | None,
    auth_apikey: str | None,
    auth_apikey_name: str,
    auth_apikey_in: str,
    oauth_client_id: str | None,
    oauth_client_secret: str | None,
    oauth_token_url: str | None,
    cookie_jar: str | None,
    reqlog: str | None,
    ssh_tunnel: str | None,
    protocol_scan: bool,
    http3: bool,
) -> ScanConfig:
    auth_method = "none"
    if auth_bearer:
        auth_method = "bearer"
    elif auth_apikey:
        auth_method = "api_key"
    elif oauth_client_id and oauth_token_url:
        auth_method = "oauth2"
    return ScanConfig(
        timeout=timeout,
        delay=delay,
        max_retries=retries,
        proxy=proxy,
        verify_tls=verify_tls,
        max_redirects=max_redirects,
        pool_maxsize=pool_size,
        pool_connections=max(2, pool_size // 2),
        auth_method=auth_method,
        auth_token=auth_bearer or "",
        auth_api_key=auth_apikey or "",
        auth_api_key_name=auth_apikey_name,
        auth_api_key_in=auth_apikey_in,
        oauth_client_id=oauth_client_id or "",
        oauth_client_secret=oauth_client_secret or "",
        oauth_token_url=oauth_token_url or "",
        cookie_jar=cookie_jar or "",
        request_logging=bool(reqlog),
        log_path=reqlog or "",
        ssh_tunnel=ssh_tunnel or "",
        protocol_scan=protocol_scan,
        enable_http3=http3,
    )


@app.callback(invoke_without_command=True)
def _main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit."
    ),
) -> None:
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command("auth")
def auth_cmd() -> None:
    """Authenticate CLI with Vercel web dashboard using device code flow."""
    from basilisk.auth import authenticate
    api_key, username = authenticate()
    if api_key:
        console.print(f"[bold green]Successfully authenticated as {username}![/bold green]")
    else:
        console.print("[bold red]Authentication failed or cancelled.[/bold red]")


@app.command("logout")
def logout_cmd() -> None:
    """Log out and remove local credentials."""
    clear_config()
    console.print("[green]Logged out successfully.[/green]")


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
    output_dir: str | None = typer.Option(None, "--output-dir", help="Save results to a directory (auto-named .json + .html)"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout"),
    web_ui: bool = typer.Option(True, "--ui/--no-ui", help="Launch ephemeral code-authenticated local session dashboard"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Automatically open web dashboard in browser"),
    cookie: str | None = typer.Option(None, "--cookie", "-c", help="Request cookies (e.g. 'session=abc; token=xyz')"),
    header: list[str] = typer.Option([], "--header", "-H", help="Extra request headers (e.g. 'X-Custom: value')"),
    proxy: str | None = typer.Option(None, "--proxy", help="Proxy URL (http://, https://, socks5://, socks5h://)"),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Skip TLS certificate validation for target requests"),
    max_redirects: int = typer.Option(10, "--max-redirects", help="Max redirects before loop detection kicks in"),
    auth_bearer: str | None = typer.Option(None, "--auth-bearer", "-B", help="Bearer token for Authorization header"),
    auth_apikey: str | None = typer.Option(None, "--auth-apikey", help="API key for custom auth"),
    auth_apikey_name: str = typer.Option("X-API-Key", "--auth-apikey-name", help="Header/param name for the API key"),
    auth_apikey_in: str = typer.Option("header", "--auth-apikey-in", help="Where to place the API key: header, query, or cookie"),
    oauth_client_id: str | None = typer.Option(None, "--oauth-client-id", help="OAuth2 client_credentials client id"),
    oauth_client_secret: str | None = typer.Option(None, "--oauth-client-secret", help="OAuth2 client_credentials secret"),
    oauth_token_url: str | None = typer.Option(None, "--oauth-token-url", help="OAuth2 token endpoint (enables client-credentials flow)"),
    pool_size: int = typer.Option(20, "--pool-size", help="Connection pool size per host"),
    cookie_jar: str | None = typer.Option(None, "--cookie-jar", help="Persist/reuse session cookies from a JSON file"),
    reqlog: str | None = typer.Option(None, "--reqlog", help="Log requests/responses to a JSON file (replayable)"),
    ssh_tunnel: str | None = typer.Option(None, "--ssh-tunnel", help="Scan via bastion host: user@host (SOCKS5 dynamic tunnel)"),
    no_protocol_scan: bool = typer.Option(False, "--no-protocol-scan", help="Skip DNS/TLS/ALPN/pipelining transport checks"),
    http3: bool = typer.Option(False, "--http3", help="Attempt HTTP/3 (QUIC) requests (requires httpx[http3])"),
) -> None:
    """Full site scan: protocol checks, recon, passive audit, Attack Engine fuzzing."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"

    extra_headers = _parse_headers(header) if header else None
    cookies = _parse_cookie(cookie) if cookie else None

    server: EphemeralDashboardServer | None = None
    if web_ui and not json_output:
        try:
            server = EphemeralDashboardServer(target_url=url)
            server.start()
            if open_browser:
                server.open_browser()
        except Exception as exc:
            logging.warning(f"Could not start local web server: {exc}")
            server = None

    if not json_output:
        _banner(url, mode=mode, server=server)

    scan_config = _build_config(
        timeout=timeout,
        delay=delay,
        retries=retries,
        proxy=proxy,
        verify_tls=not no_verify_tls,
        max_redirects=max_redirects,
        pool_size=pool_size,
        auth_bearer=auth_bearer,
        auth_apikey=auth_apikey,
        auth_apikey_name=auth_apikey_name,
        auth_apikey_in=auth_apikey_in,
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_token_url=oauth_token_url,
        cookie_jar=cookie_jar,
        reqlog=reqlog,
        ssh_tunnel=ssh_tunnel,
        protocol_scan=not no_protocol_scan,
        http3=http3,
    )

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
            config=scan_config,
        )
    except LLMError as exc:
        console.print(f"[bold red]LLM config error:[/bold red] {exc}")
        if server:
            server.stop()
        raise typer.Exit(code=2) from exc

    try:
        with Progress(
            SpinnerColumn(style="green"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            def on_progress(msg: str) -> None:
                progress.update(task, description=msg[:80])
                if server:
                    server.session.update_progress(msg)

            report = scanner.scan(
                max_pages=max_pages,
                active=not no_active,
                fuzz_url_params=not no_url_fuzz,
                on_progress=on_progress,
            )
            if server:
                server.session.set_report(report)
    except LLMError as exc:
        console.print(f"[bold red]LLM error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=130)
    finally:
        scanner.close()
        if server:
            server.stop()

    if json_output:
        console.print_json(json.dumps(report, default=str))
        if report.get("vulnerable"):
            raise typer.Exit(code=1)
        return

    console.print()
    _print_findings(report.get("findings", []))
    _print_summary(report)
    _try_upload(report)

    if output:
        _export(report, output)

    if output_dir:
        od = Path(output_dir)
        od.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        slug = url.replace("https://", "").replace("http://", "").split("/")[0].replace(".", "_")
        _export(report, str(od / f"{slug}_{ts}.json"))
        _export(report, str(od / f"{slug}_{ts}.html"))

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
    proxy: str | None = typer.Option(None, "--proxy", help="Proxy URL (http://, https://, socks5://, socks5h://)"),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Skip TLS certificate validation for target requests"),
    auth_bearer: str | None = typer.Option(None, "--auth-bearer", "-B", help="Bearer token for Authorization header"),
    ssh_tunnel: str | None = typer.Option(None, "--ssh-tunnel", help="Scan via bastion host: user@host (SOCKS5 dynamic tunnel)"),
) -> None:
    """Probe a login endpoint for SQL injection via the Attack Engine."""
    enabled, key = _resolve_llm(use_llm, no_llm, api_key)
    mode = "llm" if enabled else "static"

    extra_headers = _parse_headers(header) if header else None
    cookies = _parse_cookie(cookie) if cookie else None

    if not json_output:
        _banner(f"{url}{endpoint}", mode=mode)

    scan_config = _build_config(
        timeout=timeout,
        delay=delay,
        retries=retries,
        proxy=proxy,
        verify_tls=not no_verify_tls,
        max_redirects=10,
        pool_size=20,
        auth_bearer=auth_bearer,
        auth_apikey=None,
        auth_apikey_name="X-API-Key",
        auth_apikey_in="header",
        oauth_client_id=None,
        oauth_client_secret=None,
        oauth_token_url=None,
        cookie_jar=None,
        reqlog=None,
        ssh_tunnel=ssh_tunnel,
        protocol_scan=False,
        http3=False,
    )

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
            config=scan_config,
        )
    except LLMError as exc:
        console.print(f"[bold red]LLM config error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        with console.status("[green]Probing login endpoint...[/green]", spinner="dots"):
            report = scanner.scan_login(login_endpoint=endpoint)
    except LLMError as exc:
        console.print(f"[bold red]LLM error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=130)
    finally:
        scanner.close()

    findings = report.get("findings", [])

    if json_output:
        console.print_json(json.dumps(report, default=str))
        if report.get("vulnerable"):
            raise typer.Exit(code=1)
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

    _try_upload(report)

    if output:
        _export(report, output)

    if report.get("vulnerable"):
        raise typer.Exit(code=1)


def main() -> None:
    load_llm_env()
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
