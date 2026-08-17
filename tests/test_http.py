"""Tests for Basilisk HTTP engine — redirects, cookies, backoff, logging."""

import json
import time

from basilisk.http import RequestEngine
from tests import LocalServer


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


class TestRedirectLoopDetection:
    def test_redirect_loop_capped_and_flagged(self):
        with LocalServer() as server:
            engine = RequestEngine(timeout=2, follow_redirects=True, max_redirects=5)
            result = engine.send("GET", server.base_url + "/redirect")
            assert result is not None
            assert result["redirect_loop"] is True
            assert len(result["redirect_chain"]) >= 1
            assert result["status_code"] == 302

    def test_no_loop_flag_without_redirects(self):
        with LocalServer() as server:
            engine = RequestEngine(timeout=2)
            result = engine.send("GET", server.base_url + "/")
            assert result is not None
            assert "redirect_loop" not in result
            assert "redirect_chain" not in result

    def test_follow_redirects_disabled_keeps_302(self):
        with LocalServer() as server:
            engine = RequestEngine(timeout=2, follow_redirects=False)
            result = engine.send("GET", server.base_url + "/redirect")
            assert result is not None
            assert result["status_code"] == 302


class TestBackoffRetries:
    def test_exponential_backoff_sleeps(self):
        engine = RequestEngine(timeout=1, max_retries=3, backoff_factor=0.05)
        start = time.time()
        engine.send("GET", "http://invalid.local/test")
        elapsed = time.time() - start
        # backoff: 0.05 + up to jitter, 0.1 + jitter -> minimum ~0.15 + jitter
        assert elapsed >= 0.1

    def test_single_retry_no_sleep(self):
        engine = RequestEngine(timeout=1, max_retries=1)
        start = time.time()
        engine.send("GET", "http://invalid.local/test")
        assert time.time() - start < 3


class TestCookiePersistence:
    def test_cookies_saved_and_reloaded(self, tmp_path):
        from pathlib import Path

        jar = str(tmp_path / "cookies.json")
        with LocalServer() as server:
            engine = RequestEngine(timeout=2, cookie_jar=jar)
            engine.send("GET", server.base_url + "/setcookie")
            data = json.loads(Path(jar).read_text(encoding="utf-8"))
            assert data["cookies"].get("session") == "abc123"

            fresh = RequestEngine(timeout=2, cookie_jar=jar)
            assert fresh.get_cookies().get("session") == "abc123"

    def test_cookies_shared_in_session(self):
        with LocalServer() as server:
            engine = RequestEngine(timeout=2)
            engine.send("GET", server.base_url + "/setcookie")
            assert engine.get_cookies().get("session") == "abc123"


class TestRequestLoggingAndReplay:
    def test_log_records_and_replays(self, tmp_path):
        log_path = str(tmp_path / "reqlog.json")
        with LocalServer() as server:
            engine = RequestEngine(timeout=2, logging_enabled=True, log_path=log_path)
            result = engine.send("GET", server.base_url + "/")
            assert result["status_code"] == 200
            assert len(engine.log.entries) == 1
            entry = engine.log.entries[0]
            assert entry.status_code == 200
            assert entry.url.startswith("http://127.0.0.1")

            replay = engine.replay(entry.request_id)
            assert replay is not None
            assert replay["status_code"] == 200
            assert len(server.requests) == 2

    def test_log_saved_to_disk_and_loaded(self, tmp_path):
        from pathlib import Path

        log_path = str(tmp_path / "reqlog.json")
        with LocalServer() as server:
            engine = RequestEngine(timeout=2, logging_enabled=True, log_path=log_path)
            engine.send("GET", server.base_url + "/")
            engine.close()
            assert json.loads(Path(log_path).read_text(encoding="utf-8"))["count"] == 1

        reloaded = RequestEngine(timeout=2, logging_enabled=True, log_path=log_path)
        assert len(reloaded.log.entries) == 1

    def test_replay_unknown_id_returns_none(self, tmp_path):
        engine = RequestEngine(timeout=2, logging_enabled=True, log_path=str(tmp_path / "l.json"))
        assert engine.replay("nope") is None


class TestProxyHandling:
    def test_proxy_configured(self):
        engine = RequestEngine(timeout=1, proxy="http://127.0.0.1:8080")
        assert engine.session.proxies.get("https") == "http://127.0.0.1:8080"

    def test_no_proxy_bypasses(self):
        engine = RequestEngine(timeout=1, proxy="http://127.0.0.1:8080", no_proxy=["example.com"])
        assert engine._uses_proxy("http://example.com/") is False
        assert engine._uses_proxy("http://other.com/") is True