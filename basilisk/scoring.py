"""CVSS v3.1 Base Score Calculator for Basilisk findings."""

from __future__ import annotations

import math
from dataclasses import dataclass

# ── CVSS v3.1 metric weights ──────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_S = {"U": False, "C": True}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


@dataclass(frozen=True)
class CVSSVector:
    """Parsed CVSS v3.1 base-metric vector."""
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )

    def base_score(self) -> float:
        return calculate_base_score(self)


def calculate_base_score(v: CVSSVector) -> float:
    """Compute CVSS v3.1 base score from a parsed vector."""
    scope_changed = _S[v.scope]
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1.0 - (
        (1.0 - _CIA[v.confidentiality])
        * (1.0 - _CIA[v.integrity])
        * (1.0 - _CIA[v.availability])
    )
    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22
        * _AV[v.attack_vector]
        * _AC[v.attack_complexity]
        * pr_table[v.privileges_required]
        * _UI[v.user_interaction]
    )

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return math.ceil(raw * 10) / 10


def parse_vector(vector_string: str) -> CVSSVector:
    """Parse a CVSS:3.1/AV:N/AC:L/... string into a CVSSVector."""
    parts = vector_string.replace("CVSS:3.1/", "").split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return CVSSVector(
        attack_vector=metrics.get("AV", "N"),
        attack_complexity=metrics.get("AC", "L"),
        privileges_required=metrics.get("PR", "N"),
        user_interaction=metrics.get("UI", "N"),
        scope=metrics.get("S", "U"),
        confidentiality=metrics.get("C", "N"),
        integrity=metrics.get("I", "N"),
        availability=metrics.get("A", "N"),
    )


# ── Default CVSS vectors per attack type ──────────────────────────────────

ATTACK_CVSS_MAP: dict[str, CVSSVector] = {
    # SQL Injection — full compromise possible
    "sqli": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    "blind_sqli": CVSSVector("N", "H", "N", "N", "U", "H", "H", "N"),
    # XSS — session hijack
    "xss": CVSSVector("N", "L", "N", "R", "C", "L", "L", "N"),
    "dom_xss": CVSSVector("N", "L", "N", "R", "C", "L", "L", "N"),
    # Command injection — full RCE
    "cmdi": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    # Path traversal / LFI — file read
    "path_traversal": CVSSVector("N", "L", "N", "N", "U", "H", "N", "N"),
    "lfi": CVSSVector("N", "L", "N", "N", "U", "H", "L", "N"),
    # SSTI — code execution
    "ssti": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    "ssti_advanced": CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"),
    # SSRF — internal access
    "ssrf": CVSSVector("N", "L", "N", "N", "C", "H", "L", "N"),
    "ssrf_oob": CVSSVector("N", "L", "N", "N", "C", "H", "L", "N"),
    # Open redirect — phishing
    "open_redirect": CVSSVector("N", "L", "N", "R", "U", "N", "L", "N"),
    # NoSQL injection
    "nosqli": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),
    # Login bypass
    "login": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    # XXE — file read + SSRF
    "xxe": CVSSVector("N", "L", "N", "N", "C", "H", "N", "N"),
    # GraphQL — data exposure
    "graphql": CVSSVector("N", "L", "N", "N", "U", "H", "N", "N"),
    # BOLA / IDOR
    "bola": CVSSVector("N", "L", "L", "N", "U", "H", "H", "N"),
    # Prototype pollution
    "prototype_pollution": CVSSVector("N", "L", "N", "N", "U", "L", "L", "N"),
    # WebSocket injection
    "websocket": CVSSVector("N", "L", "N", "N", "U", "L", "L", "N"),
    # Race condition
    "race_condition": CVSSVector("N", "H", "N", "N", "U", "N", "L", "N"),
    # LDAP injection
    "ldap": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),
    # Business logic
    "business_logic": CVSSVector("N", "L", "N", "N", "U", "N", "H", "N"),
    # Info disclosure
    "info_disclosure": CVSSVector("N", "L", "N", "N", "U", "L", "N", "N"),
    # Auth bypass (JWT/OAuth)
    "auth_bypass": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    # CSRF
    "csrf": CVSSVector("N", "L", "N", "R", "U", "N", "H", "N"),
    # Privilege escalation
    "privilege_escalation": CVSSVector("N", "L", "L", "N", "U", "H", "H", "H"),
    # Credential stuffing
    "credential_stuffing": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),
    # Container escape
    "container_escape": CVSSVector("L", "H", "H", "N", "C", "H", "H", "H"),
    # Network segmentation
    "network_segmentation": CVSSVector("N", "L", "N", "N", "C", "H", "N", "N"),
    # CMS
    "cms": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    # Zero-day heuristic
    "zero_day": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
    # Payload chain — context-dependent, default high
    "payload_chain": CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"),
}


def score_finding(attack_type: str, severity_override: str | None = None) -> tuple[float, str]:
    """
    Return (cvss_score, cvss_vector_string) for a given attack type.
    Falls back to a generic vector if the type is unknown.
    """
    vector = ATTACK_CVSS_MAP.get(
        attack_type,
        CVSSVector("N", "L", "N", "N", "U", "L", "N", "N"),  # fallback
    )
    return vector.base_score(), vector.to_string()


def severity_from_score(score: float) -> str:
    """Map a CVSS score to a severity label."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Info"
