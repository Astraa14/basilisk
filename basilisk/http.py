"""HTTP session engine for Basilisk scans — protocol & transport layer.

Provides: cookie persistence, redirect loop detection (max N hops),
exponential backoff with jitter, connection pooling, HTTP/SOCKS proxy
support, custom auth hooks, and request/response logging with replay.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Basilisk/0.1"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BODY_DROP_STATUSES = {301, 302, 303}

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


@dataclass
class LoggedRequest:
    """Snapshot of a request/response pair for logging and replay."""

    request_id: str
    timestamp: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    params: dict | None = None
    data: dict | None = None
    status_code: int | None = None
    response_headers: dict = field(default_factory=dict)
    response_preview: str = ""
    elapsed: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class RequestLog:
    """Thread-safe in-memory request log with optional JSON persistence."""

    def __init__(self, path: str = ""):
        self.path = path
        self._entries: list[LoggedRequest] = []
        self._lock = threading.Lock()

    @property
    def entries(self) -> list[LoggedRequest]:
        with self._lock:
            return list(self._entries)

    def add(self, entry: LoggedRequest) -> None:
        with self._lock:
            self._entries.append(entry)
            if self.path and len(self._entries) % 25 == 0:
                self.save()

    def save(self) -> None:
        if not self.path:
            return
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = [e.to_dict() for e in self._entries]
        Path(self.path).write_text(
            json.dumps({"count": len(data), "requests": data}, indent=2),
            encoding="utf-8",
        )

    def load(self) -> int:
        if not self.path or not Path(self.path).exists():
            return 0
        try:
            data = json.loads(Path(self.path).read_text(encoding="utf-8"))
            with self._lock:
                for item in data.get("requests", []):
                    self._entries.append(LoggedRequest(**item))
            return len(data.get("requests", []))
        except Exception as exc:
            logger.debug("Failed to load request log %s: %s", self.path, exc)
            return 0

    def find(self, request_id: str) -> LoggedRequest | None:
        with self._lock:
            for e in self._entries:
                if e.request_id == request_id:
                    return e
        return None

    def filter(self, status: int | None = None, method: str | None = None) -> list[LoggedRequest]:
        result = []
        for e in self.entries:
            if status is not None and e.status_code != status:
                continue
            if method and e.method.upper() != method.upper():
                continue
            result.append(e)
        return result


class RequestEngine:
    """Session-based HTTP client used by crawl, passive, and active phases."""

    def __init__(
        self,
        timeout: float = 5,
        user_agent: str | None = None,
        delay: float = 0,
        max_retries: int = 1,
        extra_headers: dict | None = None,
        cookies: dict | None = None,
        verify_tls: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        backoff_factor: float = 1.0,
        backoff_max: float = 30.0,
        proxy: str | None = None,
        no_proxy: list[str] | None = None,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        cookie_jar: str = "",
        auth=None,
        logging_enabled: bool = False,
        log_path: str = "",
        keep_alive: bool = True,
    ):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max(1, max_retries)
        self.verify = verify_tls
        self.follow_redirects = follow_redirects
        self.max_redirects = max(10, max_redirects)
        self.backoff_factor = backoff_factor
        self.backoff_max = backoff_max
        self.keep_alive = keep_alive
        self.auth = auth
        self.cookie_jar = cookie_jar
        self.cookies_enabled = True

        self.session.headers.update({"User-Agent": user_agent or DEFAULT_UA})
        if extra_headers:
            self.session.headers.update(extra_headers)
        if cookies:
            self.session.cookies.update(cookies)

        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=0,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
            self.session.trust_env = False
            self._proxy = proxy
        else:
            self._proxy = None
            self.session.trust_env = True
        if no_proxy:
            self._no_proxy = set(no_proxy)
        else:
            self._no_proxy = set()

        self._load_cookie_jar()

        self.log: RequestLog | None = None
        if logging_enabled or log_path:
            self.log = RequestLog(log_path or "")
            self.log.load()
        self._log_lock = threading.Lock()

    # ── cookie persistence ────────────────────────────────────────────────

    def _cookie_file(self) -> Path:
        return Path(self.cookie_jar)

    def _load_cookie_jar(self) -> None:
        if not self.cookie_jar or not Path(self.cookie_jar).exists():
            return
        try:
            data = json.loads(Path(self.cookie_jar).read_text(encoding="utf-8"))
            jar = data.get("cookies", {})
            for name, value in jar.items():
                self.session.cookies.set(name, value)
            logger.debug("Loaded %d persisted cookies from %s", len(jar), self.cookie_jar)
        except Exception as exc:
            logger.debug("Cookie jar load failed for %s: %s", self.cookie_jar, exc)

    def save_cookies(self) -> None:
        if not self.cookie_jar:
            return
        try:
            jar = {c.name: c.value for c in self.session.cookies}
            Path(self.cookie_jar).parent.mkdir(parents=True, exist_ok=True)
            Path(self.cookie_jar).write_text(
                json.dumps(
                    {"cookies": jar, "updated_at": datetime.now(timezone.utc).isoformat()},
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("Cookie jar save failed for %s: %s", self.cookie_jar, exc)

    def get_cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.session.cookies}

    # ── proxy helpers ─────────────────────────────────────────────────────

    def _uses_proxy(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        for entry in self._no_proxy:
            if host == entry or host.endswith("." + entry.lstrip(".")):
                return False
        return True

    # ── request logging ───────────────────────────────────────────────────

    def _record_log(
        self,
        method: str,
        url: str,
        params: dict | None,
        data: dict | None,
        headers: dict | None,
        status_code: int | None,
        response_headers: dict,
        body: str,
        elapsed: float,
        error: str = "",
    ) -> str:
        request_id = uuid.uuid4().hex[:12]
        if self.log is None:
            return request_id
        entry = LoggedRequest(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method.upper(),
            url=url,
            headers=dict(headers or {}),
            params=dict(params) if params else None,
            data=dict(data) if data else None,
            status_code=status_code,
            response_headers=dict(response_headers),
            response_preview=(body or "")[:500],
            elapsed=elapsed,
            error=error,
        )
        self.log.add(entry)
        return request_id

    def replay(self, request_id: str, on_progress=None) -> dict | None:
        """Re-send a previously logged request, returning a fresh response dict."""
        if self.log is None:
            return None
        entry = self.log.find(request_id)
        if entry is None:
            return None
        if on_progress:
            on_progress(f"Replaying request {request_id} -> {entry.url}")
        return self.send(
            entry.method,
            entry.url,
            params=entry.params,
            data=entry.data,
            headers=entry.headers or None,
        )

    # ── main send path ────────────────────────────────────────────────────

    def send(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
        auth=None,
    ) -> dict | None:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.warning("Invalid URL skipped: %s", url)
            return None

        if self.delay > 0:
            time.sleep(self.delay)

        method = method.upper()
        effective_timeout = timeout if timeout is not None else self.timeout
        should_follow = self.follow_redirects if follow_redirects is None else follow_redirects
        use_auth = auth if auth is not None else self.auth

        last_exc: Exception | None = None
        total_attempts = self.max_retries + (
            1 if use_auth is not None and use_auth.is_refreshable else 0
        )

        for attempt in range(total_attempts):
            restore_proxies = None
            if not self._uses_proxy(url):
                restore_proxies = dict(self.session.proxies)
                self.session.proxies = {}

            req_headers = dict(self.session.headers)
            if headers:
                req_headers.update(headers)
            if not self.keep_alive:
                req_headers["Connection"] = "close"

            if use_auth is not None:
                auth_params = dict(params) if params else {}
                use_auth.apply(method, url, req_headers, auth_params)
            else:
                auth_params = params

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=auth_params,
                    data=data,
                    headers=req_headers,
                    timeout=effective_timeout,
                    allow_redirects=False,
                    verify=self.verify,
                )

                chain: list[str] = []
                loop_detected = False
                current = response
                redirect_count = 0
                while (
                    should_follow
                    and current.status_code in REDIRECT_STATUSES
                    and "Location" in current.headers
                    and redirect_count < self.max_redirects
                ):
                    location = current.headers["Location"]
                    next_url = urljoin(current.url, location)
                    if next_url in chain or (chain and next_url == chain[0]):
                        loop_detected = True
                        break
                    chain.append(next_url)
                    redirect_count += 1

                    if current.status_code in BODY_DROP_STATUSES or method == "POST":
                        follow_method = "GET"
                        follow_data = None
                    else:
                        follow_method = method
                        follow_data = data
                    if current.status_code == 303:
                        follow_method = "GET"
                        follow_data = None

                    current = self.session.request(
                        method=follow_method,
                        url=next_url,
                        params=auth_params,
                        data=follow_data,
                        headers=req_headers,
                        timeout=effective_timeout,
                        allow_redirects=False,
                        verify=self.verify,
                    )

                result = self._build_result(current, chain, loop_detected)
                if self.cookies_enabled:
                    self.save_cookies()
                if use_auth is not None and result["status_code"] == 401 and use_auth.refresh():
                    continue
                return result

            except requests.exceptions.SSLError as exc:
                logger.debug("TLS failure attempt %d/%d: %s (%s)", attempt + 1, self.max_retries, url, exc)
                last_exc = exc
            except requests.exceptions.Timeout as exc:
                logger.debug("Timeout attempt %d/%d: %s (>%ss)", attempt + 1, self.max_retries, url, effective_timeout)
                last_exc = exc
            except requests.exceptions.ConnectionError as exc:
                logger.debug("Connection failed attempt %d/%d: %s", attempt + 1, self.max_retries, url)
                last_exc = exc
            except requests.exceptions.RequestException as exc:
                logger.debug("Request error on %s: %s", url, exc)
                last_exc = exc
            finally:
                if restore_proxies is not None:
                    self.session.proxies = restore_proxies

            if attempt < self.max_retries - 1:
                self._backoff_sleep(attempt)

        self._record_log(
            method, url, params, data, headers,
            status_code=None, response_headers={}, body="",
            elapsed=0.0, error=str(last_exc) if last_exc else "unknown",
        )
        logger.debug("All %d attempts failed for %s: %s", self.max_retries, url, last_exc)
        return None

    def _backoff_sleep(self, attempt: int) -> None:
        base = min(self.backoff_factor * (2 ** attempt), self.backoff_max)
        jitter = random.uniform(0, base * 0.25)
        time.sleep(base + jitter)

    def _build_result(self, response, chain: list[str], loop_detected: bool) -> dict:
        result: dict = {
            "status_code": response.status_code,
            "url": response.url,
            "headers": dict(response.headers),
            "body": response.text,
            "elapsed_time": response.elapsed.total_seconds(),
        }
        if chain:
            result["redirect_chain"] = chain
        if loop_detected:
            result["redirect_loop"] = True
        req = response.request
        self._record_log(
            req.method if req else "",
            req.url if req else response.url,
            None,
            None,
            dict(req.headers) if req else None,
            response.status_code,
            dict(response.headers),
            response.text,
            response.elapsed.total_seconds(),
        )
        return result

    def close(self) -> None:
        if self.log is not None:
            self.log.save()
        try:
            self.session.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()
