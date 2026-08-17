"""Custom authentication methods for Basilisk requests — Bearer, OAuth2,
API Key (header/query/cookie), and HTTP Basic."""

from __future__ import annotations

import base64
import logging
import threading
import time
from enum import Enum
from urllib.parse import urlencode

import requests

from basilisk.models import ScanConfig

logger = logging.getLogger(__name__)

OAUTH_LEEWAY = 30  # seconds before expiry to consider a token stale


class AuthMethod(str, Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"


class AuthProvider:
    """Applies an authentication method to outgoing requests.

    Behaves as a hook for RequestEngine: ``apply`` mutates the request
    headers/params in place; ``refresh`` re-issues expired OAuth tokens.
    """

    def __init__(
        self,
        method: AuthMethod | str = AuthMethod.NONE,
        token: str = "",
        username: str = "",
        password: str = "",
        api_key: str = "",
        api_key_name: str = "X-API-Key",
        api_key_in: str = "header",  # header | query | cookie
        oauth_token_url: str = "",
        oauth_client_id: str = "",
        oauth_client_secret: str = "",
        oauth_scope: str = "",
        timeout: float = 10.0,
    ):
        self.method = AuthMethod(method) if not isinstance(method, AuthMethod) else method
        self.token = token
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_name = api_key_name
        self.api_key_in = api_key_in.lower()
        self.oauth_token_url = oauth_token_url
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.oauth_scope = oauth_scope
        self.timeout = timeout
        self._lock = threading.Lock()
        self._oauth_token: str | None = None
        self._oauth_token_type: str = "Bearer"
        self._oauth_expires_at: float = 0.0

    # ── factory ───────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: ScanConfig) -> AuthProvider:
        return cls(
            method=config.auth_method,
            token=config.auth_token,
            username=config.auth_basic_user,
            password=config.auth_basic_password,
            api_key=config.auth_api_key,
            api_key_name=config.auth_api_key_name,
            api_key_in=config.auth_api_key_in,
            oauth_token_url=config.oauth_token_url,
            oauth_client_id=config.oauth_client_id,
            oauth_client_secret=config.oauth_client_secret,
            oauth_scope=config.oauth_scope,
        )

    # ── public API ────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self.method is not AuthMethod.NONE

    @property
    def is_refreshable(self) -> bool:
        return self.method is AuthMethod.OAUTH2 and bool(self.oauth_token_url)

    def apply(self, method: str, url: str, headers: dict, params: dict | None = None) -> None:
        if self.method is AuthMethod.NONE:
            return
        if self.method is AuthMethod.BEARER:
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        elif self.method is AuthMethod.BASIC:
            raw = f"{self.username}:{self.password}"
            encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        elif self.method is AuthMethod.API_KEY:
            self._apply_api_key(headers, params)
        elif self.method is AuthMethod.OAUTH2:
            token = self._current_oauth_token()
            if token:
                headers["Authorization"] = f"{self._oauth_token_type} {token}"

    def refresh(self) -> bool:
        """Re-issue an OAuth token if ~expired. Returns True if usable."""
        if not self.is_refreshable:
            return False
        with self._lock:
            token = self._oauth_token
            if token and self._oauth_expires_at and time.monotonic() > self._oauth_expires_at:
                return self._fetch_oauth_token_locked()
            if not token:
                return self._fetch_oauth_token_locked()
        return True

    # ── internals ─────────────────────────────────────────────────────────

    def _apply_api_key(self, headers: dict, params: dict | None) -> None:
        if not self.api_key:
            return
        name = self.api_key_name or "X-API-Key"
        if self.api_key_in == "query":
            if params is not None:
                params[name] = self.api_key
        elif self.api_key_in == "cookie":
            existing = headers.get("Cookie", "")
            pair = f"{name}={self.api_key}"
            headers["Cookie"] = f"{pair}; {existing}" if existing else pair
        else:
            headers[name] = self.api_key

    def _current_oauth_token(self) -> str | None:
        with self._lock:
            if self._oauth_token and self._oauth_expires_at and time.monotonic() > self._oauth_expires_at:
                self._fetch_oauth_token_locked()
            return self._oauth_token

    def _fetch_oauth_token_locked(self) -> bool:
        if not self.oauth_token_url:
            return False
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
        }
        if self.oauth_scope:
            payload["scope"] = self.oauth_scope
        try:
            response = requests.post(
                self.oauth_token_url,
                data=urlencode(payload),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.debug("OAuth token request failed: %s", exc)
            return False
        access_token = data.get("access_token")
        if not access_token:
            logger.debug("OAuth token response missing access_token")
            return False
        self._oauth_token = access_token
        self._oauth_token_type = data.get("token_type", "Bearer")
        expires_in = data.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            self._oauth_expires_at = time.monotonic() + float(expires_in) - OAUTH_LEEWAY
        else:
            self._oauth_expires_at = 0.0
        logger.debug("OAuth token acquired (type=%s, expires_in=%s)", self._oauth_token_type, expires_in)
        return True