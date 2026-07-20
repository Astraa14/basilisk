"""Concurrent scanning engine — parallel crawling and fuzzing via ThreadPoolExecutor."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from urllib.parse import urlparse

from basilisk.models import Finding

logger = logging.getLogger(__name__)

ProgressCb = Callable[[str], None]


class RateLimiter:
    """Per-domain request rate limiter to avoid self-DoS."""

    def __init__(self, requests_per_second: float = 20.0):
        self._interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._domain_locks: dict[str, threading.Lock] = {}
        self._domain_last: dict[str, float] = {}
        self._global_lock = threading.Lock()

    def wait(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._global_lock:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
                self._domain_last[domain] = 0.0

        lock = self._domain_locks[domain]
        with lock:
            elapsed = time.monotonic() - self._domain_last[domain]
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._domain_last[domain] = time.monotonic()


class ConcurrentScanner:
    """Thread-pool wrapper for parallel scan operations."""

    def __init__(
        self,
        max_workers: int = 10,
        rate_limit: float = 20.0,
    ):
        self.max_workers = max(1, min(max_workers, 50))
        self.rate_limiter = RateLimiter(rate_limit)
        self._findings_lock = threading.Lock()
        self._findings: list[Finding] = []
        self._progress_lock = threading.Lock()

    def _collect_finding(self, finding: Finding) -> None:
        with self._findings_lock:
            self._findings.append(finding)

    def _collect_findings(self, findings: list[Finding]) -> None:
        with self._findings_lock:
            self._findings.extend(findings)

    def parallel_crawl(
        self,
        urls: list[str],
        fetch_fn: Callable[[str], dict | None],
        on_progress: ProgressCb | None = None,
    ) -> list[dict]:
        """Fetch multiple URLs concurrently, returning list of response dicts."""
        results: list[dict] = []
        results_lock = threading.Lock()

        def _fetch(url: str) -> dict | None:
            self.rate_limiter.wait(url)
            return fetch_fn(url)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map: dict[Future, str] = {}
            for url in urls:
                fut = pool.submit(_fetch, url)
                future_map[fut] = url

            for future in as_completed(future_map):
                url = future_map[future]
                try:
                    result = future.result()
                    if result:
                        with results_lock:
                            results.append(result)
                        if on_progress:
                            with self._progress_lock:
                                on_progress(f"Fetched {url}")
                except Exception as exc:
                    logger.debug("Concurrent fetch failed for %s: %s", url, exc)

        return results

    def parallel_fuzz(
        self,
        tasks: list[dict],
        fuzz_fn: Callable[[dict], list[Finding]],
        on_progress: ProgressCb | None = None,
    ) -> list[Finding]:
        """
        Run fuzzing tasks concurrently.

        Each task dict is passed to fuzz_fn, which returns a list of Findings.
        Tasks should contain `url` key for rate limiting.
        """
        self._findings = []

        def _run_task(task: dict) -> list[Finding]:
            url = task.get("url", task.get("action_url", ""))
            if url:
                self.rate_limiter.wait(url)
            return fuzz_fn(task)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map: dict[Future, dict] = {}
            for task in tasks:
                fut = pool.submit(_run_task, task)
                future_map[fut] = task

            completed = 0
            total = len(tasks)
            for future in as_completed(future_map):
                task = future_map[future]
                completed += 1
                try:
                    results = future.result()
                    self._collect_findings(results)
                    if on_progress:
                        with self._progress_lock:
                            on_progress(
                                f"Fuzzing [{completed}/{total}] "
                                f"{task.get('url', task.get('action_url', ''))[:50]}"
                            )
                except Exception as exc:
                    logger.debug("Fuzz task failed: %s", exc)

        return list(self._findings)

    def parallel_detect(
        self,
        urls: list[str],
        detect_fn: Callable[[str], list[Finding]],
        label: str = "Detecting",
        on_progress: ProgressCb | None = None,
    ) -> list[Finding]:
        """Run a detection function across multiple URLs concurrently."""
        self._findings = []

        def _run(url: str) -> list[Finding]:
            self.rate_limiter.wait(url)
            return detect_fn(url)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map: dict[Future, str] = {}
            for url in urls:
                fut = pool.submit(_run, url)
                future_map[fut] = url

            completed = 0
            total = len(urls)
            for future in as_completed(future_map):
                url = future_map[future]
                completed += 1
                try:
                    results = future.result()
                    self._collect_findings(results)
                    if on_progress:
                        with self._progress_lock:
                            on_progress(f"{label} [{completed}/{total}] {url[:50]}")
                except Exception as exc:
                    logger.debug("%s failed for %s: %s", label, url, exc)

        return list(self._findings)
