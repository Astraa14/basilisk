"""HTTP session engine for Basilisk scans."""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Basilisk/0.1"


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
    ):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.session.headers.update({"User-Agent": user_agent or DEFAULT_UA})
        if extra_headers:
            self.session.headers.update(extra_headers)
        if cookies:
            self.session.cookies.update(cookies)

    def send(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> dict | None:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.warning("Invalid URL skipped: %s", url)
            return None

        if self.delay > 0:
            time.sleep(self.delay)

        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                return {
                    "status_code": response.status_code,
                    "url": response.url,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "elapsed_time": response.elapsed.total_seconds(),
                }
            except requests.exceptions.Timeout as exc:
                logger.debug("Timeout attempt %d/%d: %s (>%ss)", attempt + 1, self.max_retries, url, self.timeout)
                last_exc = exc
            except requests.exceptions.ConnectionError as exc:
                logger.debug("Connection failed attempt %d/%d: %s", attempt + 1, self.max_retries, url)
                last_exc = exc
            except requests.exceptions.RequestException as exc:
                logger.debug("Request error on %s: %s", url, exc)
                last_exc = exc
            if attempt < self.max_retries - 1:
                time.sleep(1 * (attempt + 1))
        logger.debug("All %d attempts failed for %s: %s", self.max_retries, url, last_exc)
        return None
