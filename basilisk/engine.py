"""Attack Engine — orchestrates Generator -> Target -> Judge."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from basilisk.generator import PayloadGenerator
from basilisk.judge import HybridJudge
from basilisk.llm import LLMClient
from basilisk.models import Finding
from basilisk.target import WebTarget

ProgressCb = Callable[[str], None]


class AttackEngine:
    """Run static (+ optional LLM) strategies against discovered forms / login."""

    def __init__(
        self,
        target: WebTarget,
        use_llm: bool = False,
        custom_dataset: str | Path | None = None,
        llm_client: LLMClient | None = None,
    ):
        self.target = target
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

    def fuzz_forms(
        self,
        forms: list[dict],
        on_progress: ProgressCb | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for form in forms:
            key = f"{form.get('method')}:{form.get('action_url')}"
            if key in seen:
                continue
            seen.add(key)
            if on_progress:
                on_progress(f"Fuzzing {form.get('action_url')}")
            findings.extend(self._fuzz_one_form(form))

        return findings

    def _fuzz_one_form(self, form: dict) -> list[Finding]:
        if not form.get("inputs"):
            return []

        findings: list[Finding] = []

        for payload in self.generator.generate("sqli", form):
            response = self.target.submit_form(form, payload)
            if not response:
                continue
            hit = self.judge.judge("sqli", payload, response)
            if hit:
                findings.append(hit)
                break

        for payload in self.generator.generate("xss", form):
            response = self.target.submit_form(form, payload)
            if not response:
                continue
            hit = self.judge.judge("xss", payload, response)
            if hit:
                findings.append(hit)

        return findings

    def probe_login(
        self,
        base_url: str,
        login_endpoint: str = "/login",
        on_progress: ProgressCb | None = None,
    ) -> tuple[list[Finding], list[dict]]:
        findings: list[Finding] = []
        exploits: list[dict] = []
        payloads = self.generator.generate(
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
