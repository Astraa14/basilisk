"""Payload generators — HackAgent-style Generator role (+ static datasets)."""

from __future__ import annotations

from pathlib import Path

from basilisk.datasets import load_bundled, load_custom
from basilisk.llm import LLMClient, LLMError

SUPPORTED_KINDS = {
    "sqli", "xss", "cmdi", "path_traversal",
    "ssti", "ssrf", "open_redirect", "lfi", "nosqli",
}


class StaticGenerator:
    """Dataset / template payloads (Static Template strategy)."""

    def __init__(self, custom_dataset: str | Path | None = None):
        self._pools: dict[str, list[str]] = {}
        for kind in SUPPORTED_KINDS:
            try:
                self._pools[kind] = load_bundled(kind)
            except FileNotFoundError:
                self._pools[kind] = []
        if custom_dataset:
            extra = load_custom(custom_dataset)
            for kind in SUPPORTED_KINDS:
                self._pools[kind] = list(dict.fromkeys([*self._pools[kind], *extra]))

    def payloads_for(self, kind: str) -> list[str]:
        if kind == "login":
            kind = "sqli"
        if kind not in SUPPORTED_KINDS:
            raise ValueError(f"Unknown payload kind: {kind}")
        return list(self._pools.get(kind, []))


class LLMGenerator:
    SYSTEM = (
        "You are the Generator in a security red-team pipeline (authorized testing only). "
        "Your job is to create adversarial HTTP form payloads that probe for "
        "web vulnerabilities against a web application Target. "
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
        GOALS = {
            "sqli": "Bypass or break SQL-backed input handling (error-based / auth bypass / blind probes).",
            "xss": "Get a script or event-handler payload reflected unescaped in the HTML response.",
            "cmdi": "Inject OS commands via shell metacharacters to achieve command execution.",
            "path_traversal": "Traverse the filesystem using ../ patterns to read arbitrary files.",
            "ssti": "Inject server-side template expressions to evaluate arbitrary code.",
            "ssrf": "Make the server request internal resources or external attacker-controlled URLs.",
            "open_redirect": "Redirect the user to an external attacker-controlled URL.",
            "lfi": "Include local files via PHP wrappers or path traversal to read source code.",
            "nosqli": "Inject MongoDB operators ($gt, $ne, $regex) to bypass authentication or extract data.",
            "login": "Bypass login via SQL injection in the username field.",
        }
        goal = GOALS.get(kind, f"Probe for {kind} weaknesses.")

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
        resolved_kind = "sqli" if kind == "login" else kind
        seeds = self.static.payloads_for(resolved_kind)
        if not self.use_llm or self.llm is None or form_context is None:
            return seeds
        generated = self.llm.generate(kind, form_context, seeds)
        return list(dict.fromkeys([*generated, *seeds[:3]])) or seeds
