"""Device code flow authentication for Basilisk CLI (like GitHub CLI auth)."""

from __future__ import annotations

import time
import webbrowser

import requests

BACKEND_URL = "https://basilisk-ja22.onrender.com"
FRONTEND_URL = "https://basilisk-livid.vercel.app"

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
            "Make sure the backend is running (Render may need a cold start)."
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
            # 202 = still waiting; 400 after cleanup = fail later
        except requests.RequestException:
            pass
        time.sleep(POLL_INTERVAL)
    return None, None


def open_auth_browser(url: str) -> None:
    """Open the verification URL in the user's default browser."""
    webbrowser.open(url)
