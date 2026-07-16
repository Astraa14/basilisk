"""Recon phase — crawl pages, extract forms, run passive audits."""

from __future__ import annotations

from collections.abc import Callable

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
        queue = [start_url]
        visited: set[str] = set()
        findings: list[Finding] = []
        discovered_forms: list[dict] = []
        pages_scanned = 0

        if on_progress:
            on_progress(f"Starting crawl of {start_url}")

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
                if link not in visited and link not in queue:
                    queue.append(link)

            page_forms = parser.extract_forms(response["body"])
            if page_forms:
                discovered_forms.extend(page_forms)
                if on_progress:
                    on_progress(f"Found {len(page_forms)} form(s) on {current}")

        return {
            "pages_scanned": len(visited),
            "forms": discovered_forms,
            "findings": findings,
            "visited": visited,
        }
