"""Basilisk scan orchestrator — crawl, passive audit, active fuzz."""

from __future__ import annotations

from collections.abc import Callable

from basilisk.attack import ActiveFuzzer, scan_login_endpoint
from basilisk.http import RequestEngine
from basilisk.parser import DomParser
from basilisk.passive import PassiveAnalyzer

ProgressCb = Callable[[str], None]


class Basilisk:
    """Coordinate full-site and login-focused vulnerability scans."""

    def __init__(self, target_url: str, timeout: float = 5):
        self.target_url = target_url.rstrip("/")
        if not self.target_url.startswith(("http://", "https://")):
            self.target_url = "https://" + self.target_url
        self.requester = RequestEngine(timeout=timeout)
        self.analyzer = PassiveAnalyzer()
        self.fuzzer = ActiveFuzzer(requester=self.requester)

    def scan(
        self,
        max_pages: int = 15,
        active: bool = True,
        on_progress: ProgressCb | None = None,
    ) -> dict:
        """Crawl the target, run passive checks, then fuzz discovered forms."""

        def note(msg: str) -> None:
            if on_progress:
                on_progress(msg)

        queue = [self.target_url]
        visited: set[str] = set()
        findings: list[dict] = []
        discovered_forms: list[dict] = []
        pages_scanned = 0

        note(f"Starting crawl of {self.target_url}")

        while queue and pages_scanned < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue

            visited.add(current)
            pages_scanned += 1
            note(f"Crawling [{pages_scanned}/{max_pages}] {current}")

            response = self.requester.send("GET", current)
            if not response:
                continue

            findings.extend(self.analyzer.analyze(response))

            parser = DomParser(base_url=response["url"])
            for link in parser.extract_links(response["body"]):
                if link not in visited and link not in queue:
                    queue.append(link)

            page_forms = parser.extract_forms(response["body"])
            if page_forms:
                discovered_forms.extend(page_forms)
                note(f"Found {len(page_forms)} form(s) on {current}")

        if active and discovered_forms:
            note(f"Active fuzzing {len(discovered_forms)} form(s)...")
            seen_actions: set[str] = set()
            for form in discovered_forms:
                key = f"{form['method']}:{form['action_url']}"
                if key in seen_actions:
                    continue
                seen_actions.add(key)
                note(f"Fuzzing {form['action_url']}")
                findings.extend(self.fuzzer.fuzz_form(form))
        elif active:
            note("No forms discovered — skipping active fuzz")

        return {
            "target": self.target_url,
            "pages_scanned": len(visited),
            "forms_found": len(discovered_forms),
            "vulnerable": any(f.get("severity") in ("High", "Critical") for f in findings),
            "findings": findings,
        }

    def scan_login(self, login_endpoint: str = "/login") -> dict:
        """Probe a login endpoint for SQL injection."""
        return scan_login_endpoint(
            self.target_url,
            login_endpoint=login_endpoint,
            requester=self.requester,
        )
