"""
Basilisk configuration — stores backend authentication and user-configured LLM settings.
"""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".basilisk"
CONFIG_FILE = CONFIG_DIR / "config.json"


def ensure_config_dir() -> None:
    """Create ~/.basilisk/ if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _load_all() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _save_all(data: dict) -> None:
    ensure_config_dir()
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_backend_api_key(key: str, username: str = "") -> None:
    """Save backend API key and username."""
    data = _load_all()
    data["api_key"] = key
    data["username"] = username
    _save_all(data)


def load_backend_api_key() -> str | None:
    """Load backend API key if present."""
    data = _load_all()
    return data.get("api_key")


def load_backend_username() -> str | None:
    """Load backend username if present."""
    data = _load_all()
    return data.get("username")


def save_llm_config(api_key: str, base_url: str = "", model: str = "") -> None:
    """Persist the user-configured LLM API key."""
    data = _load_all()
    data["llm_api_key"] = api_key
    data["llm_base_url"] = base_url
    data["llm_model"] = model
    _save_all(data)


def load_llm_config() -> dict:
    """Return saved LLM config dict."""
    return _load_all()


def clear_config() -> None:
    """Delete the saved local config file."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


def config_exists() -> bool:
    """Return True if a config file is present."""
    return CONFIG_FILE.exists()
