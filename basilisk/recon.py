"""Recon phase — crawl pages, extract forms, run passive audits."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urljoin, urlparse

from basilisk.models import Finding
from basilisk.parser import DomParser
from basilisk.passive import PassiveAnalyzer
from basilisk.target import WebTarget

ProgressCb = Callable[[str], None]


class Recon:
    """Map the target site and collect passive findings + form vectors."""

    def __init__(self, target: WebTarget):
        self.target = target
        self.analyzer = PassiveAnalyzer()

    def crawl(
        self,
        start_url: str,
        max_pages: int = 15,
        on_progress: ProgressCb | None = None,
    ) -> dict:
        queue: list[str] = [start_url]
        visited: set[str] = set()
        findings: list[Finding] = []
        discovered_forms: list[dict] = []
        urls_with_params: list[str] = []
        pages_scanned = 0

        if on_progress:
            on_progress(f"Starting crawl of {start_url}")

        robots_urls = self._try_robots_txt(start_url)
        if robots_urls:
            if on_progress:
                on_progress(f"Robots.txt: discovered {len(robots_urls)} URL(s)")
            for rurl in robots_urls:
                if rurl not in queue and rurl not in visited:
                    queue.append(rurl)

        while queue and pages_scanned < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue

            visited.add(current)
            pages_scanned += 1
            if on_progress:
                on_progress(f"Crawling [{pages_scanned}/{max_pages}] {current}")

            response = self.target.get(current)
            if not response:
                continue

            for item in self.analyzer.analyze(response):
                findings.append(
                    Finding(
                        vulnerability=item["vulnerability"],
                        severity=item["severity"],
                        description=item["description"],
                        target=item["target"],
                    )
                )

            parser = DomParser(base_url=response["url"])
            for link in parser.extract_links(response["body"]):
                if link not in visited and link not in queue and len(visited) + len(queue) < max_pages * 3:
                    queue.append(link)

            page_forms = parser.extract_forms(response["body"])
            if page_forms:
                discovered_forms.extend(page_forms)
                if on_progress:
                    on_progress(f"Found {len(page_forms)} form(s) on {current}")

            if "?" in current:
                urls_with_params.append(current)

        return {
            "pages_scanned": len(visited),
            "forms": discovered_forms,
            "findings": findings,
            "visited": visited,
            "urls_with_params": urls_with_params,
        }

    def _try_robots_txt(self, start_url: str) -> list[str]:
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            resp = self.target.get(robots_url)
            if not resp or resp.get("status_code") != 200:
                return []
            body = resp.get("body", "")
            urls: list[str] = []
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        full_url = urljoin(start_url, path)
                        if urlparse(full_url).netloc == parsed.netloc:
                            urls.append(full_url)
            return urls
        except Exception:
            return []
