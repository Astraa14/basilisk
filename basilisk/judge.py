"""Response judges — HackAgent-style Judge role (+ heuristic signals)."""

from __future__ import annotations

from basilisk.llm import LLMClient, LLMError
from basilisk.models import Finding


class HeuristicJudge:
    """Fast signature checks used as signals / static-mode judge."""

    DB_ERRORS = [
        "sql syntax",
        "mysql_fetch",
        "native client",
        "unclosed quotation mark",
        "sqlite3.operationalerror",
        "postgresql query failed",
        "ora-00933",
        "unhandled exception",
        "internal server error",
    ]

    AUTH_INDICATORS = [
        "welcome admin",
        "admin dashboard",
    ]

    def find_db_error(self, body: str) -> str | None:
        lower = body.lower()
        for error in self.DB_ERRORS:
            if error in lower:
                return error
        return None

    def signals(self, kind: str, payload: str, response: dict) -> list[str]:
        notes: list[str] = []
        status = response.get("status_code", 0)
        body = response.get("body", "")
        if status == 500:
            notes.append("HTTP 500 Internal Server Error")
        err = self.find_db_error(body)
        if err:
            notes.append(f"DB/error signature: {err}")
        if kind in ("xss",) and payload in body:
            notes.append("Payload reflected verbatim in body")
        lower = body.lower()
        for indicator in self.AUTH_INDICATORS:
            if indicator in lower:
                notes.append(f"Auth success indicator: {indicator}")
        return notes

    def evaluate_sqli(self, response: dict, payload: str) -> Finding | None:
        status = response.get("status_code", 0)
        body = response.get("body", "")
        target = response.get("url", "")
        if status == 500:
            return Finding(
                vulnerability="Potential SQL Injection (SQLi)",
                severity="High",
                description=f"HTTP 500 after payload: {payload}",
                target=target,
            )
        error = self.find_db_error(body)
        if error:
            return Finding(
                vulnerability="Potential SQL Injection (SQLi)",
                severity="High",
                description=f"Signature '{error}' for payload: {payload}",
                target=target,
            )
        return None

    def evaluate_xss(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "")
        target = response.get("url", "")
        if payload in body:
            return Finding(
                vulnerability="Potential Reflected XSS",
                severity="High",
                description=f"Payload reflected raw: {payload}",
                target=target,
            )
        return None

    def evaluate_login(self, response: dict, payload: str) -> Finding | None:
        status = response.get("status_code", 0)
        body = response.get("body", "")
        target = response.get("url", "")
        if status == 500:
            return Finding(
                vulnerability="Potential SQL Injection (Login)",
                severity="High",
                description=f"HTTP 500 / crash indicators - payload: {payload}",
                target=target,
            )
        lower = body.lower()
        for indicator in self.DB_ERRORS + self.AUTH_INDICATORS:
            if indicator in lower:
                return Finding(
                    vulnerability="Potential SQL Injection (Login)",
                    severity="High",
                    description=f"Auth bypass or DB leak ('{indicator}') - payload: {payload}",
                    target=target,
                )
        return None

    def evaluate(self, kind: str, payload: str, response: dict) -> Finding | None:
        if kind == "sqli":
            return self.evaluate_sqli(response, payload)
        if kind == "xss":
            return self.evaluate_xss(response, payload)
        if kind == "login":
            return self.evaluate_login(response, payload)
        return None


class LLMJudge:
    """
    HackAgent-style Judge role: LLM decides whether the attack on the Target succeeded.
    Heuristic signals are provided as evidence, not as the final decision.
    """

    SYSTEM = (
        "You are the Judge in a security red-team pipeline (authorized testing only). "
        "Given an attack payload and the Target's HTTP response, decide if the attack "
        "successfully demonstrated SQL injection, auth bypass, or reflected XSS. "
        "Use the heuristic signals as supporting evidence, but make your own decision. "
        "Reply with JSON only: "
        '{"vulnerable": bool, "severity": "High"|"Medium"|"Low"|"Info", "reason": string}.'
    )

    def __init__(self, client: LLMClient | None = None):
        self.client = client or LLMClient()
        self.heuristic = HeuristicJudge()

    def evaluate(
        self,
        kind: str,
        payload: str,
        response: dict,
    ) -> Finding | None:
        signals = self.heuristic.signals(kind, payload, response)
        body = response.get("body", "")[:2500]
        user = (
            f"Attack kind: {kind}\n"
            f"Payload sent to Target: {payload}\n"
            f"HTTP status: {response.get('status_code')}\n"
            f"Final URL: {response.get('url')}\n"
            f"Heuristic signals: {signals or ['none']}\n"
            f"Response body excerpt:\n{body}\n"
            "Did this attack succeed against the Target?"
        )
        try:
            data = self.client.chat_json(self.SYSTEM, user, temperature=0.1)
        except LLMError:
            # Fall back to heuristics if Judge LLM fails
            return self.heuristic.evaluate(kind, payload, response)
        if not isinstance(data, dict) or not data.get("vulnerable"):
            return None
        label = {
            "sqli": "Potential SQL Injection (SQLi)",
            "xss": "Potential Reflected XSS",
            "login": "Potential SQL Injection (Login)",
        }.get(kind, f"Potential issue ({kind})")
        return Finding(
            vulnerability=label,
            severity=str(data.get("severity", "Medium")),
            description=f"[Judge] {data.get('reason', 'LLM flagged response as vulnerable')}",
            target=response.get("url", ""),
        )


class HybridJudge:
    """
    LLM mode: Judge role is primary (HackAgent-style).
    Static mode: heuristic signatures only.
    """

    def __init__(self, use_llm: bool = False, llm_client: LLMClient | None = None):
        self.use_llm = use_llm
        self.heuristic = HeuristicJudge()
        self.llm = LLMJudge(client=llm_client) if use_llm else None

    def judge(self, kind: str, payload: str, response: dict) -> Finding | None:
        if self.use_llm and self.llm:
            return self.llm.evaluate(kind, payload, response)
        return self.heuristic.evaluate(kind, payload, response)
