"""Device code flow authentication for Basilisk CLI (like GitHub CLI auth)."""

from __future__ import annotations

import time
import webbrowser

import requests

# Update these constants after production deployment (Task 4.5)
BACKEND_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:3000"

DEVICE_CODE_ENDPOINT = f"{BACKEND_URL}/api/auth/device-code"
TOKEN_ENDPOINT = f"{BACKEND_URL}/api/auth/token"

POLL_INTERVAL = 2   # seconds between polls
TIMEOUT = 60        # seconds before giving up


def request_device_code() -> dict:
    """
    Call the backend to generate a device code.

    Returns a dict with: device_code, user_code, verification_uri, expires_in.
    Raises RuntimeError if the backend is unreachable.
    """
    try:
        response = requests.post(DEVICE_CODE_ENDPOINT, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Could not reach Basilisk backend at {BACKEND_URL}. "
            "Make sure the backend is running."
        ) from exc


def poll_for_backend_key(device_code: str) -> str | None:
    """
    Poll the backend until the user confirms in browser or timeout is reached.

    Returns the api_key string on success, or None on timeout.
    """
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            resp = requests.post(
                TOKEN_ENDPOINT,
                json={"device_code": device_code},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == 200 and data.get("api_key"):
                    return data["api_key"], data.get("username", "")
            # 202 = still waiting, continue polling
        except requests.RequestException:
            pass  # network hiccup — keep trying
        time.sleep(POLL_INTERVAL)
    return None, None


def open_auth_browser(url: str) -> None:
    """Open the verification URL in the user's default browser."""
    webbrowser.open(url)
