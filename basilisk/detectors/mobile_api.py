"""Mobile API security testing — endpoint discovery and Insecure Direct Object Reference."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


MOBILE_API_PATHS = [
    "/api/mobile", "/api/app", "/mobile", "/app",
    "/api/v1/mobile", "/api/v2/mobile",
    "/api/user/sync", "/api/data/sync",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
]

MOBILE_SECURITY_CHECKS = [
    {"name": "App Transport Security", "patterns": ["http://", "ws://"]},
    {"name": "API Key in URL", "patterns": ["?api_key=", "&api_key=", "?apikey=", "&apikey="]},
    {"name": "Session Token in URL", "patterns": ["?token=", "&token=", "?session=", "&session="]},
    {"name": "PII in Response", "patterns": ["device_id", "imei", "mac_address", "advertising_id"]},
]

MOBILE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36",
    "Accept": "application/json",
    "X-Platform": "android",
    "X-App-Version": "3.2.1",
    "X-Device-ID": "test-device-001",
}


def detect_mobile_api_issues(
    response: dict, path: str, target: str = ""
) -> list[Finding]:
    findings: list[Finding] = []
    body = response.get("body", "")
    url = response.get("url", target)
    status = response.get("status_code", 0)
    lower_body = body.lower()

    # Check for API key or token in URL
    for check in MOBILE_SECURITY_CHECKS:
        for pattern in check["patterns"]:
            if pattern in url.lower():
                cvss, vector = score_finding("mobile_api")
                findings.append(
                    Finding(
                        vulnerability=f"Mobile API: {check['name']}",
                        severity="High",
                        description=f"Security issue '{check['name']}' detected in mobile API endpoint: {path}.",
                        target=target,
                        attack_type="mobile_api",
                        payload=path,
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Never include API keys or tokens in URL parameters. Use Authorization headers.",
                    )
                )
                break

    # Check for PII in response
    for check in MOBILE_SECURITY_CHECKS:
        if check["name"] == "PII in Response":
            for pattern in check["patterns"]:
                if pattern in lower_body:
                    cvss, vector = score_finding("mobile_api")
                    findings.append(
                        Finding(
                            vulnerability="Mobile API: PII Leakage",
                            severity="High",
                            description=f"Potentially sensitive PII field '{pattern}' found in mobile API response.",
                            target=target,
                            attack_type="mobile_api",
                            payload=path,
                            cvss_score=cvss,
                            cvss_vector=vector,
                            remediation="Minimize PII in API responses. Implement field-level access controls.",
                        )
                    )
                    break

    # Check for unencrypted HTTP (App Transport Security bypass)
    if path.startswith("http://"):
        cvss, vector = score_finding("mobile_api")
        findings.append(
            Finding(
                vulnerability="Mobile API: Insecure HTTP Transport",
                severity="Critical",
                description=f"Mobile API endpoint uses unencrypted HTTP: {path}. App Transport Security bypass.",
                target=target,
                attack_type="mobile_api",
                payload=path,
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Enforce HTTPS for all mobile API communications. Implement certificate pinning.",
            )
        )

    return findings


def get_mobile_paths() -> list[str]:
    return list(MOBILE_API_PATHS)

def get_mobile_headers() -> dict[str, str]:
    return dict(MOBILE_HEADERS)
