"""Credential stuffing detection — common credentials and response timing analysis."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


COMMON_CREDENTIALS: list[dict] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "admin123"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "admin1234"},
    {"username": "admin", "password": "letmein"},
    {"username": "user", "password": "user"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "toor"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "qwerty"},
    {"username": "admin", "password": "welcome"},
    {"username": "admin", "password": "passw0rd"},
]

CREDENTIAL_ENDPOINTS = ["/login", "/api/login", "/auth", "/api/auth", "/signin"]


def detect_no_rate_limiting(responses: list[dict], target: str = "") -> Finding | None:
    if len(responses) < 5:
        return None

    success_count = sum(1 for r in responses if r.get("status_code", 0) in (200, 201, 202))
    responses_allowed = sum(1 for r in responses if r.get("status_code", 0) != 429)

    if success_count >= 1:
        cvss, vector = score_finding("credential_stuffing")
        return Finding(
            vulnerability="Weak Credentials Accepted",
            severity="High",
            description=f"Common credential combination successfully authenticated (HTTP 200) in {success_count}/{len(responses)} attempts.",
            target=target,
            attack_type="credential_stuffing",
            payload="brute_force: common credentials",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Enforce strong password policies, implement account lockout, and use MFA.",
        )

    if responses_allowed == len(responses):
        cvss, vector = score_finding("credential_stuffing")
        return Finding(
            vulnerability="Missing Rate Limiting on Login",
            severity="Medium",
            description=f"No rate limiting detected: all {len(responses)} login attempts returned non-429 responses.",
            target=target,
            attack_type="credential_stuffing",
            payload=f"{len(responses)} rapid login attempts",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Implement rate limiting and account lockout on authentication endpoints.",
        )

    return None


def detect_timing_anomaly(responses: list[dict], target: str = "") -> Finding | None:
    if len(responses) < 3:
        return None

    elapsed_times = [r.get("elapsed_time", 0) for r in responses if r.get("elapsed_time")]
    if len(elapsed_times) < 3:
        return None

    avg_time = sum(elapsed_times) / len(elapsed_times)
    min_time = min(elapsed_times)
    max_time = max(elapsed_times)

    if max_time - min_time < 0.05:
        cvss, vector = score_finding("credential_stuffing")
        return Finding(
            vulnerability="User Enumeration via Uniform Response Time",
            severity="Low",
            description=f"Login response times are nearly identical ({max_time - min_time:.4f}s variance). Username enumeration may not be possible via timing, but consistent timing suggests generic error messages.",
            target=target,
            attack_type="credential_stuffing",
            confidence=0.3,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Use consistent error messages and response timing for both valid and invalid usernames.",
        )

    return None


def get_credentials() -> list[dict]:
    return list(COMMON_CREDENTIALS)

def get_endpoints() -> list[str]:
    return list(CREDENTIAL_ENDPOINTS)
