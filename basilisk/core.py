"""Basilisk facade — wires Recon + Attack Engine (HackAgent-style pipeline)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from basilisk.engine import AttackEngine
from basilisk.llm import LLMClient
from basilisk.models import ScanReport
from basilisk.recon import Recon
from basilisk.target import WebTarget

ProgressCb = Callable[[str], None]


class Basilisk:
    """Coordinate recon and active attacks against a live web app."""

    def __init__(
        self,
        target_url: str,
        timeout: float = 5,
        use_llm: bool = False,
        custom_dataset: str | Path | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        delay: float = 0,
        max_retries: int = 1,
        extra_headers: dict | None = None,
        cookies: dict | None = None,
    ):
        self.target_url = target_url.rstrip("/")
        if not self.target_url.startswith(("http://", "https://")):
            self.target_url = "https://" + self.target_url
        self.use_llm = use_llm
        self.custom_dataset = custom_dataset
        self.target = WebTarget(
            timeout=timeout,
            delay=delay,
            max_retries=max_retries,
            extra_headers=extra_headers,
            cookies=cookies,
        )
        self.recon = Recon(self.target)
        llm_client = (
            LLMClient(api_key=api_key, base_url=base_url, model=model) if use_llm else None
        )
        self.engine = AttackEngine(
            target=self.target,
            use_llm=use_llm,
            custom_dataset=custom_dataset,
            llm_client=llm_client,
        )

    def scan(
        self,
        max_pages: int = 15,
        active: bool = True,
        fuzz_url_params: bool = True,
        on_progress: ProgressCb | None = None,
    ) -> dict:
        def note(msg: str) -> None:
            if on_progress:
                on_progress(msg)

        recon_result = self.recon.crawl(
            self.target_url,
            max_pages=max_pages,
            on_progress=on_progress,
        )
        findings = list(recon_result["findings"])
        forms = recon_result["forms"]
        param_urls = recon_result.get("urls_with_params", [])

        if active and forms:
            note(f"Active fuzzing {len(forms)} form(s)...")
            findings.extend(self.engine.fuzz_forms(forms, on_progress=on_progress))
        elif active:
            note("No forms discovered - skipping form fuzzing")

        if active and fuzz_url_params and param_urls:
            note(f"Fuzzing {len(param_urls)} URL(s) with parameters...")
            findings.extend(self.engine.fuzz_url_params(param_urls, on_progress=on_progress))

        report = ScanReport(
            target=self.target_url,
            pages_scanned=recon_result["pages_scanned"],
            forms_found=len(forms),
            findings=findings,
            vulnerable=any(f.severity in ("High", "Critical") for f in findings),
            mode="llm" if self.use_llm else "static",
        )
        return report.to_dict()

    def scan_login(self, login_endpoint: str = "/login", on_progress: ProgressCb | None = None) -> dict:
        findings, exploits = self.engine.probe_login(
            self.target_url,
            login_endpoint=login_endpoint,
            on_progress=on_progress,
        )
        from urllib.parse import urljoin

        full_url = urljoin(self.target_url.rstrip("/") + "/", login_endpoint.lstrip("/"))
        report = ScanReport(
            target=full_url,
            findings=findings,
            exploits_found=exploits,
            vulnerable=bool(findings),
            mode="llm" if self.use_llm else "static",
        )
        return report.to_dict()
