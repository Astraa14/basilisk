"""Tests for AuthProvider — Bearer, Basic, API Key, and OAuth2 flows."""

import base64
import time

from basilisk.auth_methods import AuthMethod, AuthProvider
from basilisk.models import ScanConfig


class TestHeaderMethods:
    def test_bearer_token(self):
        provider = AuthProvider(method=AuthMethod.BEARER, token="sekrit")
        headers = {}
        provider.apply("GET", "https://example.com/", headers)
        assert headers["Authorization"] == "Bearer sekrit"

    def test_basic_auth(self):
        provider = AuthProvider(
            method=AuthMethod.BASIC, username="user", password="pass"
        )
        headers = {}
        provider.apply("GET", "https://example.com/", headers)
        expected = base64.b64encode(b"user:pass").decode("ascii")
        assert headers["Authorization"] == f"Basic {expected}"

    def test_api_key_header(self):
        provider = AuthProvider(method=AuthMethod.API_KEY, api_key="k123")
        headers = {}
        provider.apply("GET", "https://example.com/", headers)
        assert headers["X-API-Key"] == "k123"

    def test_api_key_query(self):
        provider = AuthProvider(
            method=AuthMethod.API_KEY,
            api_key="k123",
            api_key_name="apikey",
            api_key_in="query",
        )
        params = {"existing": "1"}
        provider.apply("GET", "https://example.com/", {}, params)
        assert params["apikey"] == "k123"
        assert params["existing"] == "1"

    def test_api_key_cookie(self):
        provider = AuthProvider(
            method=AuthMethod.API_KEY,
            api_key="k123",
            api_key_name="session",
            api_key_in="cookie",
        )
        headers = {"Cookie": "other=1"}
        provider.apply("GET", "https://example.com/", headers)
        assert "session=k123" in headers["Cookie"]

    def test_none_does_nothing(self):
        provider = AuthProvider(method=AuthMethod.NONE)
        headers = {}
        provider.apply("GET", "https://example.com/", headers)
        assert headers == {}


class TestOAuth2:
    def test_token_fetch_and_apply(self, monkeypatch):
        calls = []

        def fake_post(url, data=None, headers=None, timeout=None):
            calls.append(url)
            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {"access_token": "tok123", "token_type": "Bearer", "expires_in": 3600}

            return Resp()

        monkeypatch.setattr("basilisk.auth_methods.requests.post", fake_post)
        provider = AuthProvider(
            method=AuthMethod.OAUTH2,
            oauth_token_url="https://idp.example.com/token",
            oauth_client_id="cid",
            oauth_client_secret="csec",
            oauth_scope="scan",
        )
        assert provider.refresh() is True
        headers = {}
        provider.apply("GET", "https://api.example.com/", headers)
        assert headers["Authorization"] == "Bearer tok123"
        assert len(calls) == 1

    def test_expired_token_refreshes(self, monkeypatch):
        auth_responses = iter(
            [
                {"access_token": "first", "token_type": "Bearer", "expires_in": 3600},
                {"access_token": "second", "token_type": "Bearer", "expires_in": 3600},
            ]
        )

        def fake_post(url, data=None, headers=None, timeout=None):
            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return next(auth_responses)

            return Resp()

        monkeypatch.setattr("basilisk.auth_methods.requests.post", fake_post)
        provider = AuthProvider(
            method=AuthMethod.OAUTH2,
            oauth_token_url="https://idp.example.com/token",
            oauth_client_id="cid",
            oauth_client_secret="csec",
        )
        assert provider.refresh() is True
        assert provider._oauth_token == "first"
        provider._oauth_expires_at = time.monotonic() - 5
        headers = {}
        provider.apply("GET", "https://api.example.com/", headers)
        assert headers["Authorization"] == "Bearer second"

    def test_failed_fetch(self, monkeypatch):
        def fake_post(url, data=None, headers=None, timeout=None):
            raise RuntimeError("boom")

        monkeypatch.setattr("basilisk.auth_methods.requests.post", fake_post)
        provider = AuthProvider(
            method=AuthMethod.OAUTH2,
            oauth_token_url="https://idp.example.com/token",
            oauth_client_id="cid",
            oauth_client_secret="csec",
        )
        assert provider.refresh() is False
        headers = {}
        provider.apply("GET", "https://api.example.com/", headers)
        assert "Authorization" not in headers


class TestFromConfig:
    def test_from_config_bearer(self):
        config = ScanConfig(auth_method="bearer", auth_token="t1")
        provider = AuthProvider.from_config(config)
        headers = {}
        provider.apply("GET", "https://example.com/", headers)
        assert headers["Authorization"] == "Bearer t1"

    def test_from_config_none(self):
        provider = AuthProvider.from_config(ScanConfig())
        assert provider.is_active is False