"""Device code flow authentication for Basilisk CLI (like GitHub CLI auth)."""

from __future__ import annotations

import os
import time
import webbrowser
import requests
from rich.console import Console

from basilisk.config import save_backend_api_key

console = Console(legacy_windows=False)

BACKEND_URL = os.getenv("BASILISK_BACKEND_URL", "https://basilisk-ja22.onrender.com")
FRONTEND_URL = os.getenv("BASILISK_FRONTEND_URL", "https://basilisk-livid.vercel.app")

DEVICE_CODE_ENDPOINT = f"{BACKEND_URL}/api/auth/device-code"
TOKEN_ENDPOINT = f"{BACKEND_URL}/api/auth/token"

POLL_INTERVAL = 2  # seconds between polls
TIMEOUT = 180  # allow Render cold starts


def request_device_code() -> dict:
    """
    Call the backend to generate a device code.

    Returns a dict with: device_code, user_code, verification_uri, expires_in.
    Raises RuntimeError if the backend is unreachable.
    """
    try:
        response = requests.post(DEVICE_CODE_ENDPOINT, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Could not reach Basilisk backend at {BACKEND_URL}. "
            "Make sure the backend is running."
        ) from exc


def poll_for_backend_key(device_code: str) -> tuple[str | None, str | None]:
    """
    Poll the backend until the user confirms in browser or timeout is reached.

    Returns (api_key, username) on success, or (None, None) on timeout.
    """
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            resp = requests.post(
                TOKEN_ENDPOINT,
                json={"device_code": device_code},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == 200 and data.get("api_key"):
                    return data["api_key"], data.get("username") or ""
        except requests.RequestException:
            pass
        time.sleep(POLL_INTERVAL)
    return None, None


def open_auth_browser(url: str) -> None:
    """Open the verification URL in the user's default browser."""
    webbrowser.open(url)


def authenticate() -> tuple[str | None, str | None]:
    """
    Execute full device code flow:
    1. Request code from backend
    2. Prompt user to open browser and enter code
    3. Poll backend for confirmation
    4. Save API key to local config
    """
    try:
        data = request_device_code()
    except Exception as exc:
        console.print(f"[bold red]Authentication error:[/bold red] {exc}")
        return None, None

    user_code = data.get("user_code", "")
    device_code = data.get("device_code", "")
    verification_uri = data.get("verification_uri") or f"{FRONTEND_URL}/auth"

    if "?code=" in verification_uri:
        auth_url = verification_uri
    else:
        auth_url = f"{verification_uri}?code={user_code}"

    console.print("\n[bold cyan]1.[/bold cyan] Open this URL in your browser:")
    console.print(f"   [bold yellow]{auth_url}[/bold yellow]\n")
    console.print(f"[bold cyan]2.[/bold cyan] Enter device code: [bold white on blue] {user_code} [/bold white on blue]\n")

    open_auth_browser(auth_url)

    with console.status("[dim]Waiting for browser confirmation...[/dim]", spinner="dots"):
        api_key, username = poll_for_backend_key(device_code)

    if api_key:
        save_backend_api_key(api_key, username or "")
        return api_key, username
    else:
        return None, None
