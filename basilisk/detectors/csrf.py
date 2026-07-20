"""CSRF (Cross-Site Request Forgery) detection — token analysis and missing protections."""

from __future__ import annotations

import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


CSRF_TOKEN_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "_csrf", "csrf-token",
    "xsrf-token", "x-csrf-token", "x-xsrf-token",
    "__csrf", "authenticity_token", "csrf", "_token",
    "security_token", "csrf_token_", "csrftoken",
]

SAME_SITE_VALUES = {"strict", "lax", "none"}

CSRF_UNSAFE_METHODS = ["POST", "PUT", "DELETE", "PATCH"]


def analyze_form_for_csrf(form: dict, response_headers: dict) -> Finding | None:
    action = form.get("action_url", "")
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])

    if method not in CSRF_UNSAFE_METHODS:
        return None

    input_names = [i.get("name", "").lower() for i in inputs]

    has_csrf = any(
        any(pattern in name for pattern in CSRF_TOKEN_NAMES)
        for name in input_names
    )

    if not has_csrf:
        cvss, vector = score_finding("csrf")
        return Finding(
            vulnerability="Missing CSRF Protection (Form)",
            severity="Medium",
            description=f"Form at {action} (method: {method}) has no CSRF token field. {len(inputs)} input(s) found.",
            target=action,
            attack_type="csrf",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Add CSRF tokens to all state-changing forms. Use SameSite cookies and anti-CSRF headers.",
        )

    return None


def analyze_cookie_attributes(response: dict, target: str = "") -> Finding | None:
    headers = response.get("headers", {})
    set_cookie = headers.get("Set-Cookie", "")

    if not set_cookie:
        return None

    cookie_lower = set_cookie.lower()

    if "samesite" not in cookie_lower or "samesite=none" in cookie_lower:
        cvss, vector = score_finding("csrf")
        return Finding(
            vulnerability="Missing SameSite Cookie Attribute",
            severity="Low",
            description="Session/authentication cookie set without SameSite attribute. Risk of CSRF-based session hijacking.",
            target=target,
            attack_type="csrf",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Set SameSite=Strict or SameSite=Lax on session and auth cookies.",
        )

    if "secure" not in cookie_lower:
        cvss, vector = score_finding("csrf")
        return Finding(
            vulnerability="Missing Secure Cookie Flag",
            severity="Low",
            description="Cookie set without Secure flag — may be transmitted over unencrypted HTTP.",
            target=target,
            attack_type="csrf",
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
            remediation="Set Secure flag on all sensitive cookies.",
        )

    return None


def get_token_names() -> list[str]:
    return list(CSRF_TOKEN_NAMES)
