"""HTTP session engine for Basilisk scans."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Basilisk/0.1"


class RequestEngine:
    """Session-based HTTP client used by crawl, passive, and active phases."""

    def __init__(self, timeout: float = 5, user_agent: str | None = None):
        self.session = requests.Session()
        self.timeout = timeout
        self.session.headers.update({"User-Agent": user_agent or DEFAULT_UA})

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
                "raw": response,
            }
        except requests.exceptions.Timeout:
            logger.debug("Timeout: %s (>%ss)", url, self.timeout)
        except requests.exceptions.ConnectionError:
            logger.debug("Connection failed: %s", url)
        except requests.exceptions.RequestException as exc:
            logger.debug("Request error on %s: %s", url, exc)
        return None
