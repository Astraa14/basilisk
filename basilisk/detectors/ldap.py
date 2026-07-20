"""LDAP injection detection."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding

LDAP_PAYLOADS = [
    # Basic filters
    "*",
    "*)(uid=*))(|(uid=*",
    # Authentication bypass
    "admin*\" or \"1\"=\"1",
    "admin)(!(&(|",
    # Blind
    "*)(uid=*a*",
    "*)(uid=*b*",
]

LDAP_ERRORS = [
    "supplied argument is not a valid ldap",
    "javax.naming.NameNotFoundException",
    "ldap_search_ext",
    "IPWorksASP.LDAP",
    "Protocol error",
    "Size limit exceeded",
    "Operations error",
]

def get_payloads() -> list[str]:
    return LDAP_PAYLOADS


def detect_ldap(response: dict, payload: str) -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)
    target = response.get("url", "")
    
    lower_body = body.lower()
    
    # Error-based detection
    for err in LDAP_ERRORS:
        if err.lower() in lower_body:
            cvss, vector = score_finding("ldap")
            return Finding(
                vulnerability="LDAP Injection",
                severity="High",
                description=f"LDAP error '{err}' encountered. Payload: {payload}",
                target=target,
                attack_type="ldap",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Sanitize user input used in LDAP search filters.",
            )
            
    # Auth bypass detection heuristic
    if status == 200 and ("welcome" in lower_body or "dashboard" in lower_body) and ("*" in payload or ")(" in payload):
         cvss, vector = score_finding("ldap")
         return Finding(
                vulnerability="Potential LDAP Injection (Auth Override)",
                severity="High",
                description=f"Possible authentication bypass using LDAP wildcards. Payload: {payload}",
                target=target,
                attack_type="ldap",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                confidence=0.7,
            )

    return None
