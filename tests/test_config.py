"""Tests for Basilisk config manager."""

import json
from pathlib import Path
from basilisk.config import (
    save_backend_api_key, load_backend_api_key,
    load_backend_username, clear_config, config_exists,
)


def test_save_and_load_backend_key(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_backend_api_key("bsk_test123", "testuser")
    assert config_exists()
    assert load_backend_api_key() == "bsk_test123"
    assert load_backend_username() == "testuser"


def test_load_without_config_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")
    assert load_backend_api_key() is None


def test_clear_config(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    save_backend_api_key("bsk_test")
    assert config_exists()
    clear_config()
    assert not config_exists()


def test_corrupted_config_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr("basilisk.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("basilisk.config.CONFIG_FILE", tmp_path / "config.json")

    (tmp_path / "config.json").write_text("{invalid json", encoding="utf-8")
    assert load_backend_api_key() is None
