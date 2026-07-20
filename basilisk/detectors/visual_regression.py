"""Visual regression detection — identify layout changes from injected content."""

from __future__ import annotations

import hashlib
import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


VISUAL_SOURCE_ATTRS = [
    "src", "href", "action", "data-src", "poster",
    "background", "style", "onerror", "onload",
]

UNSAFE_CSS_PATTERNS = [
    r"expression\(.*\)",
    r"url\(javascript:.*\)",
    r"-moz-binding",
    r"behavior:\s*url",
    r"@import\s+url",
]


def detect_content_injection(body: str, payload: str, target: str = "") -> Finding | None:
    lower_body = body.lower()
    lower_payload = payload.lower()

    if lower_payload[:30] in lower_body:
        cvss, vector = score_finding("visual_regression")
        return Finding(
            vulnerability="Visual Regression: Content Injection",
            severity="Medium",
            description=f"Injected content reflected in page. Payload found in rendered output: {payload[:60]}",
            target=target,
            attack_type="visual_regression",
            payload=payload[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Apply contextual output encoding. Use Content Security Policy to restrict script/style execution.",
        )

    return None


def detect_css_injection(body: str, payload: str, target: str = "") -> Finding | None:
    lower_body = body.lower()

    for pattern in UNSAFE_CSS_PATTERNS:
        if re.search(pattern, lower_body):
            cvss, vector = score_finding("visual_regression")
            return Finding(
                vulnerability="Visual Regression: CSS Injection",
                severity="High",
                description=f"Unsafe CSS pattern detected. Potential CSS injection via payload: {payload[:60]}",
                target=target,
                attack_type="visual_regression",
                payload=payload[:80],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Use Content Security Policy with style-src restrictions. Sanitize CSS inputs.",
            )

    return None


def detect_dom_clobbering(response: dict, target: str = "") -> Finding | None:
    """Detect DOM clobbering via id/name attributes."""
    body = response.get("body", "")

    clobbering_patterns = [
        r'id\s*=\s*["\'](?:ad|applet|area|form|img|layer|link|object|embed|script|style|title)["\']',
        r'name\s*=\s*["\'](?:ad|applet|area|form|img|layer|link|object|embed|script|style|title)["\']',
    ]

    for pattern in clobbering_patterns:
        if re.search(pattern, body, re.I):
            cvss, vector = score_finding("visual_regression")
            return Finding(
                vulnerability="DOM Clobbering Possible",
                severity="Medium",
                description=f"Element with clobberable id/name attribute found. May enable DOM clobbering attacks.",
                target=target,
                attack_type="visual_regression",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Avoid using id/name attributes that shadow global DOM properties.",
            )

    return None


def compute_page_hash(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def compare_page_hashes(original_hash: str, new_hash: str, target: str = "") -> Finding | None:
    if original_hash and new_hash and original_hash != new_hash:
        cvss, vector = score_finding("visual_regression")
        return Finding(
            vulnerability="Visual Regression: Page Content Changed",
            severity="Low",
            description=f"Page content hash changed from {original_hash} to {new_hash}. Unexpected content modification detected.",
            target=target,
            attack_type="visual_regression",
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.3,
            remediation="Monitor page integrity. Implement Subresource Integrity (SRI) for external resources.",
        )

    return None
