"""Advanced Server-Side Template Injection (SSTI) detection across multiple engines."""

from __future__ import annotations

import re
from dataclasses import dataclass

from basilisk.models import Finding
from basilisk.scoring import score_finding

@dataclass
class SSTIEngine:
    name: str
    payloads: list[str]
    success_pattern: str


SSTI_ENGINES = [
    SSTIEngine(
        name="Jinja2 / Twig",
        payloads=["{{7*7}}", "{{7*'7'}}"],
        success_pattern=r"49|7777777",
    ),
    SSTIEngine(
        name="Freemarker",
        payloads=["${7*7}", "${7*'7'}"],
        success_pattern=r"49|7777777",
    ),
    SSTIEngine(
        name="Velocity",
        payloads=["#set($x=7*7)$x"],
        success_pattern=r"49",
    ),
    SSTIEngine(
        name="Smarty",
        payloads=["{math equation=\"7*7\"}"],
        success_pattern=r"49",
    ),
    SSTIEngine(
        name="EJS",
        payloads=["<%= 7*7 %>"],
        success_pattern=r"49",
    ),
    SSTIEngine(
        name="Mako",
        payloads=["${7*7}"],
        success_pattern=r"49",
    ),
    # Exploitation payloads for specific engines to check for RCE
    SSTIEngine(
        name="Jinja2 (Exploit)",
        payloads=["{{ self.__class__.__mro__[1].__subclasses__() }}"],
        success_pattern=r"(&lt;|<\?)class",
    ),
]


def get_payloads() -> list[str]:
    payloads = []
    for engine in SSTI_ENGINES:
        payloads.extend(engine.payloads)
    return payloads


def detect_ssti_advanced(response: dict, payload: str) -> Finding | None:
    """Evaluate response for SSTI evaluation."""
    body = response.get("body", "")
    target = response.get("url", "")
    
    for engine in SSTI_ENGINES:
        if payload in engine.payloads:
            if re.search(engine.success_pattern, body):
                # Ensure the payload itself wasn't just reflected
                if payload not in body:
                    cvss, vector = score_finding("ssti_advanced")
                    
                    # Higher severity if it's an exploit payload
                    severity = "Critical" if "Exploit" in engine.name else "High"
                    
                    return Finding(
                        vulnerability=f"Server-Side Template Injection ({engine.name})",
                        severity=severity,
                        description=f"Template expression evaluated. Engine: {engine.name}. Payload: {payload}",
                        target=target,
                        attack_type="ssti_advanced",
                        payload=payload,
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Use logic-less templates or strict sandboxing. Avoid passing user input directly to template engines.",
                    )
                    
    # Fallback to general generic checks if not explicitly matched above
    if "49" in body and "7*7" in payload and payload not in body:
        cvss, vector = score_finding("ssti")
        return Finding(
            vulnerability="Potential Server-Side Template Injection",
            severity="High",
            description=f"Expression '7*7' evaluated to '49'. Payload: {payload}",
            target=target,
            attack_type="ssti_advanced",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
        )

    return None
