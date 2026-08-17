"""Tests for Basilisk config manager (local LLM config only)."""

import json
from pathlib import Path
from basilisk.config import (
    save_llm_config, load_llm_config,
    clear_config, config_exists,
)


def test_save_and_load_llm_config(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_llm_config("sk-test123", "https://api.openai.com/v1", "gpt-4o-mini")
    assert config_exists()
    cfg = load_llm_config()
    assert cfg.get("llm_api_key") == "sk-test123"
    assert cfg.get("llm_base_url") == "https://api.openai.com/v1"
    assert cfg.get("llm_model") == "gpt-4o-mini"


def test_load_without_config_returns_empty_dict(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")
    assert load_llm_config() == {}


def test_clear_config(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_llm_config("sk-test")
    assert config_exists()
    clear_config()
    assert not config_exists()


def test_corrupted_config_returns_empty_dict(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    (tmp_path / "config.json").write_text("{invalid json", encoding="utf-8")
    assert load_llm_config() == {}


def test_legacy_shims_are_noops(tmp_path, monkeypatch):
    """Removed SaaS shims must exist but do nothing harmful."""
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    from basilisk.config import save_backend_api_key, load_backend_api_key, load_backend_username
    # save is a no-op — must not raise
    save_backend_api_key("any_key", "any_user")
    # load always returns None (no backend)
    assert load_backend_api_key() is None
    assert load_backend_username() is None
