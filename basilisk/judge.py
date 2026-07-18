"""Response judges — HackAgent-style Judge role (+ heuristic signals)."""

from __future__ import annotations

import re
import time

from basilisk.llm import LLMClient, LLMError
from basilisk.models import Finding


class HeuristicJudge:
    DB_ERRORS = [
        "sql syntax", "mysql_fetch", "native client",
        "unclosed quotation mark", "sqlite3.operationalerror",
        "postgresql query failed", "ora-00933",
        "unhandled exception", "internal server error",
        "you have an error in your sql syntax",
        "warning: mysql", "odbc driver", "microsoft ole db",
        "supplied argument is not a valid mysql",
        "division by zero in sql", "unclosed string",
    ]

    TIME_PATTERNS = [
        re.compile(r"sleep\(\d+\)", re.I),
        re.compile(r"waitfor\s+delay", re.I),
        re.compile(r"pg_sleep\(", re.I),
        re.compile(r"benchmark\((\d+),", re.I),
    ]

    CMDI_SIGNATURES = [
        "uid=", "gid=", "groups=", "root:",
        "bin:", "daemon:", "linux version",
        "microsoft windows", "volume in drive",
        "directory of", "total bytes",
        "0_0", "www-data",
    ]

    PATH_TRAVERSAL_SIGNATURES = [
        "root:x:", "daemon:x:", "bin:x:",
        "[extensions]", "; for 16-bit app support",
        "windows registry", "localhost",
        "default home page",
    ]

    SSTI_SIGNATURES = [
        "49", "__class__", "__mro__", "__subclasses__",
        "<built-in", "<class", "selfdict",
    ]

    SSRF_SIGNATURES = [
        "ec2", "meta-data", "iam", "security-credentials",
        "computeMetadata", "ssh-rsa", "private-key",
    ]

    LFI_SIGNATURES = [
        "root:x:", "daemon:x:", "<?php", "<?=",
        "DB_HOST", "DB_USER", "DB_PASSWORD",
        "define('DB_", "$db_", "app.debug",
        "mysql_connect", "mysqli_connect",
    ]

    AUTH_INDICATORS = ["welcome admin", "admin dashboard", "logout"]

    def find_db_error(self, body: str) -> str | None:
        lower = body.lower()
        for error in self.DB_ERRORS:
            if error in lower:
                return error
        return None

    def has_timing_indicator(self, elapsed: float, body: str) -> bool:
        if elapsed >= 4.0:
            lower = body.lower()
            for pat in self.TIME_PATTERNS:
                if pat.search(lower):
                    return True
            if elapsed >= 5.0:
                return True
        return False

    def signals(self, kind: str, payload: str, response: dict) -> list[str]:
        notes: list[str] = []
        status = response.get("status_code", 0)
        body = response.get("body", "")
        elapsed = response.get("elapsed_time", 0)
        if status == 500:
            notes.append("HTTP 500 Internal Server Error")
        err = self.find_db_error(body)
        if err:
            notes.append(f"DB/error signature: {err}")
        if kind in ("xss",) and payload in body:
            notes.append("Payload reflected verbatim in body")
        if self.has_timing_indicator(elapsed, body):
            notes.append("Timing anomaly detected (possible blind injection)")
        if kind in ("ssrf", "open_redirect") and status in (301, 302, 303, 307, 308):
            location = response.get("headers", {}).get("Location", "")
            if location:
                notes.append(f"Redirect to: {location}")
        if kind in ("cmdi",) and any(sig in body.lower() for sig in self.CMDI_SIGNATURES):
            notes.append("Command execution signature detected")
        if kind in ("path_traversal", "lfi") and any(sig in body for sig in self.PATH_TRAVERSAL_SIGNATURES):
            notes.append("File content signature detected")
        lower = body.lower()
        for indicator in self.AUTH_INDICATORS:
            if indicator in lower:
                notes.append(f"Auth success indicator: {indicator}")
        return notes

    def evaluate_sqli(self, response: dict, payload: str) -> Finding | None:
        status = response.get("status_code", 0)
        body = response.get("body", "")
        target = response.get("url", "")
        elapsed = response.get("elapsed_time", 0)
        if status == 500:
            return Finding(
                vulnerability="Potential SQL Injection (SQLi)",
                severity="High",
                description=f"HTTP 500 after payload: {payload}",
                target=target, attack_type="sqli", payload=payload,
            )
        error = self.find_db_error(body)
        if error:
            return Finding(
                vulnerability="Potential SQL Injection (SQLi)",
                severity="High",
                description=f"Signature '{error}' for payload: {payload}",
                target=target, attack_type="sqli", payload=payload,
            )
        if self.has_timing_indicator(elapsed, body):
            return Finding(
                vulnerability="Potential Blind SQL Injection (Time-based)",
                severity="High",
                description=f"Timing anomaly ({elapsed:.1f}s) for payload: {payload}",
                target=target, attack_type="sqli", payload=payload,
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
                target=target, attack_type="xss", payload=payload,
            )
        stripped = payload.replace('"', "").replace("'", "")
        if len(stripped) > 10 and stripped in body:
            return Finding(
                vulnerability="Potential Reflected XSS (partial reflection)",
                severity="Medium",
                description=f"Payload partially reflected (stripped quotes): {payload}",
                target=target, attack_type="xss", payload=payload,
            )
        return None

    def evaluate_cmdi(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "").lower()
        target = response.get("url", "")
        elapsed = response.get("elapsed_time", 0)
        if any(sig in body for sig in self.CMDI_SIGNATURES):
            return Finding(
                vulnerability="Potential Command Injection",
                severity="Critical",
                description=f"Command output signature detected for payload: {payload}",
                target=target, attack_type="cmdi", payload=payload,
            )
        if elapsed >= 3.0 and any(cmd in payload.lower() for cmd in ["sleep", "ping", "timeout"]):
            return Finding(
                vulnerability="Potential Blind Command Injection (Time-based)",
                severity="High",
                description=f"Timing anomaly ({elapsed:.1f}s) for payload: {payload}",
                target=target, attack_type="cmdi", payload=payload,
            )
        return None

    def evaluate_path_traversal(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "")
        target = response.get("url", "")
        if any(sig in body for sig in self.PATH_TRAVERSAL_SIGNATURES):
            return Finding(
                vulnerability="Potential Path Traversal / File Read",
                severity="High",
                description=f"File content signature for payload: {payload}",
                target=target, attack_type="path_traversal", payload=payload,
            )
        if any(p in body for p in ["Warning: include(", "Warning: require(", "failed to open stream"]):
            return Finding(
                vulnerability="Potential Path Traversal (Error-based)",
                severity="Medium",
                description=f"Include error signature for payload: {payload}",
                target=target, attack_type="path_traversal", payload=payload,
            )
        return None

    def evaluate_ssti(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "")
        target = response.get("url", "")
        if "49" in body and "7*7" in payload:
            return Finding(
                vulnerability="Potential Server-Side Template Injection (SSTI)",
                severity="Critical",
                description=f"Expression evaluated (7*7=49) for payload: {payload}",
                target=target, attack_type="ssti", payload=payload,
            )
        if any(sig in body for sig in self.SSTI_SIGNATURES):
            return Finding(
                vulnerability="Potential Server-Side Template Injection (SSTI)",
                severity="High",
                description=f"Object introspection signature for payload: {payload}",
                target=target, attack_type="ssti", payload=payload,
            )
        return None

    def evaluate_ssrf(self, response: dict, payload: str) -> Finding | None:
        status = response.get("status_code", 0)
        target = response.get("url", "")
        body = response.get("body", "")
        if status in (301, 302, 303, 307, 308):
            location = response.get("headers", {}).get("Location", "")
            if location and "127.0.0.1" in location or "localhost" in location:
                return Finding(
                    vulnerability="Potential SSRF (Redirect to Internal)",
                    severity="High",
                    description=f"Redirect to internal address: {location}",
                    target=target, attack_type="ssrf", payload=payload,
                )
        if any(sig in body for sig in self.SSRF_SIGNATURES):
            return Finding(
                vulnerability="Potential SSRF (Cloud Metadata)",
                severity="Critical",
                description=f"Cloud metadata endpoint returned data for: {payload}",
                target=target, attack_type="ssrf", payload=payload,
            )
        if status == 200 and ("200" in str(status) or "OK" in body):
            if payload.startswith(("http://127.", "http://localhost", "file://")):
                return Finding(
                    vulnerability="Potential SSRF (Internal Resource Access)",
                    severity="Medium",
                    description=f"Internal resource returned HTTP {status} for: {payload}",
                    target=target, attack_type="ssrf", payload=payload,
                )
        return None

    def evaluate_open_redirect(self, response: dict, payload: str) -> Finding | None:
        status = response.get("status_code", 0)
        target = response.get("url", "")
        if status in (301, 302, 303, 307, 308):
            location = response.get("headers", {}).get("Location", "")
            if location and any(domain in location for domain in [".com", ".org", ".net", ".io"]):
                if "//" in location and "//" + target.split("/")[2] not in location:
                    return Finding(
                        vulnerability="Potential Open Redirect",
                        severity="Medium",
                        description=f"Redirects to external URL: {location}",
                        target=target, attack_type="open_redirect", payload=payload,
                    )
            if location and location.startswith("//"):
                return Finding(
                    vulnerability="Potential Open Redirect (Protocol-relative)",
                    severity="Medium",
                    description=f"Redirects to protocol-relative URL: {location}",
                    target=target, attack_type="open_redirect", payload=payload,
                )
        return None

    def evaluate_lfi(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "")
        target = response.get("url", "")
        if any(sig in body for sig in self.LFI_SIGNATURES):
            return Finding(
                vulnerability="Potential Local File Inclusion (LFI)",
                severity="Critical",
                description=f"Sensitive file content detected for payload: {payload}",
                target=target, attack_type="lfi", payload=payload,
            )
        if any(enc in payload for enc in ["php://", "expect://", "file://"]):
            if len(body) > 100:
                return Finding(
                    vulnerability="Potential Local File Inclusion (Wrapper)",
                    severity="High",
                    description=f"PHP wrapper returned {len(body)} bytes for: {payload}",
                    target=target, attack_type="lfi", payload=payload,
                )
        return None

    def evaluate_nosqli(self, response: dict, payload: str) -> Finding | None:
        body = response.get("body", "").lower()
        target = response.get("url", "")
        status = response.get("status_code", 0)
        if status == 200 and ("welcome" in body or "dashboard" in body or "logged in" in body):
            if any(op in payload for op in ["$gt", "$ne", "$regex", "||"]):
                return Finding(
                    vulnerability="Potential NoSQL Injection (Auth Bypass)",
                    severity="High",
                    description=f"Successful auth bypass for payload: {payload}",
                    target=target, attack_type="nosqli", payload=payload,
                )
        if status == 200 and "[" not in body and "{" not in body and len(body) > 0:
            if "$where" in payload or "$gt" in payload:
                return Finding(
                    vulnerability="Potential NoSQL Injection (Data Extraction)",
                    severity="Medium",
                    description=f"Non-empty response for operator payload: {payload}",
                    target=target, attack_type="nosqli", payload=payload,
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
                target=target, attack_type="sqli", payload=payload,
            )
        lower = body.lower()
        for indicator in self.DB_ERRORS + self.AUTH_INDICATORS:
            if indicator in lower:
                return Finding(
                    vulnerability="Potential SQL Injection (Login)",
                    severity="High",
                    description=f"Auth bypass or DB leak ('{indicator}') - payload: {payload}",
                    target=target, attack_type="sqli", payload=payload,
                )
        if "set-cookie" in {k.lower() for k in response.get("headers", {})} and status in (302, 200):
            if any(indicator in lower for indicator in self.AUTH_INDICATORS):
                return Finding(
                    vulnerability="Potential SQL Injection (Login)",
                    severity="High",
                    description=f"Auth bypass with session cookie - payload: {payload}",
                    target=target, attack_type="sqli", payload=payload,
                )
        return None

    def evaluate(self, kind: str, payload: str, response: dict) -> Finding | None:
        dispatch = {
            "sqli": self.evaluate_sqli,
            "xss": self.evaluate_xss,
            "cmdi": self.evaluate_cmdi,
            "path_traversal": self.evaluate_path_traversal,
            "ssti": self.evaluate_ssti,
            "ssrf": self.evaluate_ssrf,
            "open_redirect": self.evaluate_open_redirect,
            "lfi": self.evaluate_lfi,
            "nosqli": self.evaluate_nosqli,
            "login": self.evaluate_login,
        }
        fn = dispatch.get(kind)
        return fn(response, payload) if fn else None


class LLMJudge:
    SYSTEM = (
        "You are the Judge in a security red-team pipeline (authorized testing only). "
        "Given an attack payload and the Target's HTTP response, decide if the attack "
        "successfully demonstrated SQL injection, command injection, XSS, path traversal, "
        "SSTI, SSRF, open redirect, LFI, NoSQL injection, or auth bypass. "
        "Use the heuristic signals as supporting evidence, but make your own decision. "
        "Reply with JSON only: "
        '{"vulnerable": bool, "severity": "Critical"|"High"|"Medium"|"Low"|"Info", "reason": string}.'
    )

    def __init__(self, client: LLMClient | None = None):
        self.client = client or LLMClient()
        self.heuristic = HeuristicJudge()

    def evaluate(self, kind: str, payload: str, response: dict) -> Finding | None:
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
            return self.heuristic.evaluate(kind, payload, response)
        if not isinstance(data, dict) or not data.get("vulnerable"):
            return None
        label = {
            "sqli": "Potential SQL Injection (SQLi)",
            "xss": "Potential Reflected XSS",
            "cmdi": "Potential Command Injection",
            "path_traversal": "Potential Path Traversal",
            "ssti": "Potential Server-Side Template Injection",
            "ssrf": "Potential SSRF",
            "open_redirect": "Potential Open Redirect",
            "lfi": "Potential Local File Inclusion",
            "nosqli": "Potential NoSQL Injection",
            "login": "Potential SQL Injection (Login)",
        }.get(kind, f"Potential issue ({kind})")
        return Finding(
            vulnerability=label,
            severity=str(data.get("severity", "Medium")),
            description=f"[Judge] {data.get('reason', 'LLM flagged response as vulnerable')}",
            target=response.get("url", ""),
            attack_type=kind,
            payload=payload,
        )


class HybridJudge:
    def __init__(self, use_llm: bool = False, llm_client: LLMClient | None = None):
        self.use_llm = use_llm
        self.heuristic = HeuristicJudge()
        self.llm = LLMJudge(client=llm_client) if use_llm else None

    def judge(self, kind: str, payload: str, response: dict) -> Finding | None:
        if self.use_llm and self.llm:
            return self.llm.evaluate(kind, payload, response)
        return self.heuristic.evaluate(kind, payload, response)
