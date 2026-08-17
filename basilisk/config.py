"""
Basilisk local configuration — stores user-configured LLM settings only.

Basilisk is a fully standalone local CLI scanner.
No Basilisk backend, dashboard, or account is required.
The only keys stored here are user-configured LLM provider keys.
"""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".basilisk"
CONFIG_FILE = CONFIG_DIR / "config.json"


def ensure_config_dir() -> None:
    """Create ~/.basilisk/ if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_llm_config(api_key: str, base_url: str = "", model: str = "") -> None:
    """Persist the user-configured LLM API key (and optional endpoint/model) to disk."""
    ensure_config_dir()
    data = {"llm_api_key": api_key, "llm_base_url": base_url, "llm_model": model}
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_llm_config() -> dict:
    """Return saved LLM config dict, or empty dict if not configured."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def clear_config() -> None:
    """Delete the saved local config file."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


def config_exists() -> bool:
    """Return True if a config file is present."""
    return CONFIG_FILE.exists()


# ---------------------------------------------------------------------------
# Legacy shims — kept so existing code that imports these names doesn't crash
# during the transition.  They are no-ops / return None.
# ---------------------------------------------------------------------------

def save_backend_api_key(key: str, username: str = "") -> None:  # noqa: ARG001
    """Deprecated: Basilisk no longer has a backend. This is a no-op."""


def load_backend_api_key() -> None:
    """Deprecated: Basilisk no longer has a backend. Always returns None."""
    return None


def load_backend_username() -> None:
    """Deprecated: Basilisk no longer has a backend. Always returns None."""
    return None
