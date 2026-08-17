"""Tests for Basilisk config manager."""

import json
from pathlib import Path
from basilisk.config import (
    save_llm_config, load_llm_config,
    save_backend_api_key, load_backend_api_key, load_backend_username,
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


def test_save_and_load_backend_key(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_backend_api_key("bsk_key123", "test_user")
    assert config_exists()
    assert load_backend_api_key() == "bsk_key123"
    assert load_backend_username() == "test_user"


def test_load_without_config_returns_empty_dict(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")
    assert load_llm_config() == {}
    assert load_backend_api_key() is None


def test_clear_config(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_llm_config("sk-test")
    assert config_exists()
    clear_config()
    assert not config_exists()
