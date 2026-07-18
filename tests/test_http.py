"""Tests for Basilisk HTTP engine."""

import pytest
from basilisk.http import RequestEngine


class TestRequestEngine:
    def test_invalid_url_returns_none(self):
        engine = RequestEngine(timeout=1)
        result = engine.send("GET", "not-a-url")
        assert result is None

    def test_empty_url_returns_none(self):
        engine = RequestEngine(timeout=1)
        result = engine.send("GET", "")
        assert result is None

    def test_delay_param(self):
        import time
        engine = RequestEngine(timeout=1, delay=0.1)
        start = time.time()
        engine.send("GET", "http://invalid.local/test")
        elapsed = time.time() - start
        assert elapsed >= 0.09

    def test_extra_headers_stored(self):
        engine = RequestEngine(timeout=1, extra_headers={"X-Test": "value"})
        assert engine.session.headers.get("X-Test") == "value"

    def test_custom_user_agent(self):
        engine = RequestEngine(timeout=1, user_agent="TestAgent/1.0")
        assert engine.session.headers.get("User-Agent") == "TestAgent/1.0"
