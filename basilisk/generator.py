"""Payload generators — HackAgent-style Generator role (+ static datasets)."""

from __future__ import annotations

from pathlib import Path

from basilisk.datasets import load_bundled, load_custom
from basilisk.llm import LLMClient, LLMError


class StaticGenerator:
    """Dataset / template payloads (Static Template strategy)."""

    def __init__(self, custom_dataset: str | Path | None = None):
        self.sqli = load_bundled("sqli")
        self.xss = load_bundled("xss")
        if custom_dataset:
            extra = load_custom(custom_dataset)
            self.sqli = list(dict.fromkeys([*self.sqli, *extra]))

    def payloads_for(self, kind: str) -> list[str]:
        if kind == "sqli":
            return list(self.sqli)
        if kind == "xss":
            return list(self.xss)
        raise ValueError(f"Unknown payload kind: {kind}")


class LLMGenerator:
    """
    HackAgent-style Generator role: an LLM that creates adversarial probes
    for the web Target (SQLi / XSS), using datasets only as seed context.
    """

    SYSTEM = (
        "You are the Generator in a security red-team pipeline (authorized testing only). "
        "Your job is to create adversarial HTTP form payloads that probe for "
        "SQL injection or reflected XSS against a web application Target. "
        "Be creative and produce distinct short payloads. "
        "Return a JSON array of strings only — no markdown, no commentary."
    )

    def __init__(self, client: LLMClient | None = None, max_payloads: int = 6):
        self.client = client or LLMClient()
        self.max_payloads = max_payloads

    def generate(self, kind: str, form_context: dict, seeds: list[str]) -> list[str]:
        fields = ", ".join(
            f"{inp.get('name')} ({inp.get('type', 'text')})"
            for inp in form_context.get("inputs", [])
        )
        goal = {
            "sqli": "Bypass or break SQL-backed input handling (error-based / auth bypass probes).",
            "xss": "Get a script or event-handler payload reflected unescaped in the HTML response.",
            "login": "Bypass login via SQL injection in the username field.",
        }.get(kind, f"Probe for {kind} weaknesses.")

        user = (
            f"Attack goal: {goal}\n"
            f"Kind: {kind}\n"
            f"Target endpoint: {form_context.get('action_url', 'unknown')}\n"
            f"HTTP method: {form_context.get('method', 'post')}\n"
            f"Form fields: {fields or '(none listed)'}\n"
            f"Seed examples from dataset (inspiration only): {', '.join(seeds[:4])}\n"
            f"Produce up to {self.max_payloads} new distinct payload strings as a JSON array."
        )
        try:
            data = self.client.chat_json(self.SYSTEM, user, temperature=0.7)
        except LLMError:
            return []
        if not isinstance(data, list):
            return []
        out: list[str] = []
        for item in data:
            text = str(item).strip()
            if text and text not in out:
                out.append(text)
            if len(out) >= self.max_payloads:
                break
        return out


class PayloadGenerator:
    """
    When LLM is on: Generator role is primary (HackAgent-style), static seeds fallback.
    When LLM is off: static templates only.
    """

    def __init__(
        self,
        use_llm: bool = False,
        custom_dataset: str | Path | None = None,
        llm_client: LLMClient | None = None,
    ):
        self.static = StaticGenerator(custom_dataset=custom_dataset)
        self.use_llm = use_llm
        self.llm = LLMGenerator(client=llm_client) if use_llm else None

    def generate(self, kind: str, form_context: dict | None = None) -> list[str]:
        seeds = self.static.payloads_for(kind if kind != "login" else "sqli")
        if not self.use_llm or self.llm is None or form_context is None:
            return seeds

        generated = self.llm.generate(kind, form_context, seeds)
        # Generator-first: LLM payloads lead; keep a few static seeds as baseline
        return list(dict.fromkeys([*generated, *seeds[:3]])) or seeds
