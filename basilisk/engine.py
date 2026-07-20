"""Attack Engine — orchestrates Generator -> Target -> Judge."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from basilisk.adaptive import AdaptiveEngine, calculate_fitness
from basilisk.concurrent import ConcurrentScanner
from basilisk.generator import PayloadGenerator, SUPPORTED_KINDS
from basilisk.judge import HybridJudge
from basilisk.llm import LLMClient
from basilisk.models import Finding, ScanConfig
from basilisk.target import WebTarget

ProgressCb = Callable[[str], None]


class AttackEngine:
    """Run static (+ optional LLM/adaptive) strategies against discovered forms / login / URL params."""

    def __init__(
        self,
        target: WebTarget,
        use_llm: bool = False,
        custom_dataset: str | Path | None = None,
        llm_client: LLMClient | None = None,
        config: ScanConfig | None = None,
    ):
        self.target = target
        self.config = config or ScanConfig()
        self.use_llm = use_llm
        client = llm_client
        if use_llm:
            client = client or LLMClient()
            client.require_configured()
        self.generator = PayloadGenerator(
            use_llm=use_llm,
            custom_dataset=custom_dataset,
            llm_client=client,
        )
        self.judge = HybridJudge(use_llm=use_llm, llm_client=client)
        self.concurrent = ConcurrentScanner(max_workers=self.config.concurrency)
        self.adaptive = AdaptiveEngine() if self.config.adaptive else None

    def fuzz_forms(self, forms: list[dict], on_progress: ProgressCb | None = None) -> list[Finding]:
        if self.config.concurrency > 1:
            tasks = []
            seen: set[str] = set()
            for form in forms:
                key = f"{form.get('method')}:{form.get('action_url')}"
                if key in seen:
                    continue
                seen.add(key)
                tasks.append(form)
            return self.concurrent.parallel_fuzz(tasks, self._fuzz_one_form, on_progress=on_progress)

        findings: list[Finding] = []
        seen = set()
        for form in forms:
            key = f"{form.get('method')}:{form.get('action_url')}"
            if key in seen:
                continue
            seen.add(key)
            if on_progress:
                on_progress(f"Fuzzing form at {form.get('action_url')}")
            findings.extend(self._fuzz_one_form(form))
        return findings

    def fuzz_url_params(
        self,
        urls: list[str],
        on_progress: ProgressCb | None = None,
    ) -> list[Finding]:
        urls_with_params = [u for u in urls if "?" in u]
        if self.config.concurrency > 1 and urls_with_params:
            return self.concurrent.parallel_detect(
                urls_with_params,
                self._fuzz_url,
                label="Fuzzing URL params",
                on_progress=on_progress,
            )
        findings: list[Finding] = []
        for url in urls_with_params:
            if on_progress:
                on_progress(f"Fuzzing URL params: {url}")
            findings.extend(self._fuzz_url(url))
        return findings

    def _fuzz_one_form(self, form: dict) -> list[Finding]:
        if not form.get("inputs"):
            return []
        findings: list[Finding] = []
        for kind in ["sqli", "xss", "cmdi", "ssti", "nosqli"]:
            if kind not in SUPPORTED_KINDS:
                continue
            for payload in self._get_payloads(kind, form):
                response = self.target.submit_form(form, payload)
                if not response:
                    continue
                hit = self.judge.judge(kind, payload, response)
                if hit:
                    findings.append(hit)
                    break
        return findings

    def _fuzz_url(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        params_to_test = self._extract_param_names(url)
        for kind in ["sqli", "xss", "cmdi", "ssti", "ssrf", "open_redirect", "lfi", "path_traversal", "nosqli"]:
            if kind not in SUPPORTED_KINDS:
                continue
            for payload in self._get_payloads(kind, None):
                for param in params_to_test:
                    response = self.target.submit_url_param(url, param, payload)
                    if not response:
                        continue
                    hit = self.judge.judge(kind, payload, response)
                    if hit:
                        findings.append(hit)
                        break
                if findings and findings[-1].attack_type == kind:
                    break
        return findings

    def _get_payloads(self, kind: str, context: dict | None) -> list[str]:
        base_payloads = list(self.generator.generate(kind, context))
        if self.adaptive and base_payloads:
            def fitness_fn(p: str) -> float:
                resp = self.target.submit_url_param(
                    self.target.base_url or "",
                    "q",
                    p,
                ) if context is None else self.target.submit_form(context, p)
                return calculate_fitness(resp, p, kind)
            evolved = self.adaptive.evolve(base_payloads[:10], fitness_fn)
            evolved_payloads = [c.payload for c in evolved if c.fitness > 0]
            seen = set(base_payloads)
            for ep in evolved_payloads:
                if ep not in seen:
                    base_payloads.append(ep)
                    seen.add(ep)
        return base_payloads

    def probe_login(
        self,
        base_url: str,
        login_endpoint: str = "/login",
        on_progress: ProgressCb | None = None,
    ) -> tuple[list[Finding], list[dict]]:
        findings: list[Finding] = []
        exploits: list[dict] = []
        payloads = self._get_payloads(
            "sqli",
            {"action_url": login_endpoint, "inputs": [{"name": "username", "type": "text"}]},
        )[:6]

        for payload in payloads:
            if on_progress:
                on_progress(f"Login probe payload: {payload[:40]}")
            response = self.target.submit_login(base_url, login_endpoint, payload)
            if not response:
                break
            hit = self.judge.judge("login", payload, response)
            if hit:
                findings.append(hit)
                exploits.append(
                    {
                        "payload": payload,
                        "status_code": response.get("status_code"),
                        "reason": hit.description,
                    }
                )
        return findings, exploits

    def _extract_param_names(self, url: str) -> list[str]:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys()) or ["q", "id", "page", "file", "path", "url", "redirect"]
