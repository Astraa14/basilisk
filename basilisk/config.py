"""Local configuration manager — stores backend API key in ~/.basilisk/config.json."""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".basilisk"
CONFIG_FILE = CONFIG_DIR / "config.json"


def ensure_config_dir() -> None:
    """Create ~/.basilisk/ if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_backend_api_key(key: str, username: str = "") -> None:
    """Persist the backend API key (and optional username) to disk."""
    ensure_config_dir()
    data = {"api_key": key, "username": username}
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_backend_api_key() -> str | None:
    """Return the saved backend API key, or None if not configured."""
    if not CONFIG_FILE.exists():
        return None
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data.get("api_key") or None
    except Exception:
        return None


def load_backend_username() -> str | None:
    """Return the saved username, or None if not configured."""
    if not CONFIG_FILE.exists():
        return None
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data.get("username") or None
    except Exception:
        return None


def clear_config() -> None:
    """Delete the saved config file (logout)."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


def config_exists() -> bool:
    """Return True if a config file is present."""
    return CONFIG_FILE.exists()
