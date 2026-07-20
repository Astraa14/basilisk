"""Information disclosure detection — sensitive data leakage in responses."""

from __future__ import annotations

import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


SENSITIVE_PATTERNS: list[dict] = [
    {"pattern": r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----", "name": "Private Key", "severity": "Critical"},
    {"pattern": r"AKIA[0-9A-Z]{16}", "name": "AWS Access Key ID", "severity": "Critical"},
    {"pattern": r"(?i)sql dump|-- MySQL dump|-- PostgreSQL dump|-- Dump completed", "name": "Database Dump", "severity": "Critical"},
    {"pattern": r"sk_live_[0-9a-zA-Z]{24}", "name": "Stripe Live Key", "severity": "Critical"},
    {"pattern": r"pk_live_[0-9a-zA-Z]{24}", "name": "Stripe Live Publishable", "severity": "High"},
    {"pattern": r"(?i)secret.*=.*['\"][0-9a-zA-Z]{32,}", "name": "Hardcoded Secret", "severity": "High"},
    {"pattern": r"(?i)password.*=.*['\"][^'\"]{4,}", "name": "Hardcoded Password", "severity": "High"},
    {"pattern": r"(?i)(api[_-]?key|api[_-]?secret).*['\"][0-9a-zA-Z]{16,}", "name": "API Key/Secret", "severity": "High"},
    {"pattern": r"(?i)token.*=.*['\"][0-9a-zA-Z._-]{8,}", "name": "Token Leak", "severity": "Medium"},
    {"pattern": r"(?i)server.*internal.*ip|internal.*address.*10\.\d+\.\d+\.\d+", "name": "Internal IP Disclosure", "severity": "Medium"},
    {"pattern": r"(?i)(stack|trace|debug).*error|error.*on line \d+", "name": "Debug/Error Stack Trace", "severity": "Medium"},
    {"pattern": r"(?i)(environment|env|mode).*(production|development|staging)", "name": "Environment Disclosure", "severity": "Low"},
    {"pattern": r"(?i)x-powered-by|x-aspnet-version|x-aspnetmvc-version", "name": "Technology Stack Disclosure", "severity": "Low"},
    {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "name": "SSN (US Social Security)", "severity": "Critical"},
    {"pattern": r"(?i)jdbc:mysql://|jdbc:postgresql://|jdbc:oracle:", "name": "Database Connection String", "severity": "High"},
    {"pattern": r"(?i)s3\.amazonaws\.com/[a-zA-Z0-9._-]+", "name": "S3 Bucket URL", "severity": "Medium"},
    {"pattern": r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,}", "name": "GitHub Token", "severity": "High"},
    {"pattern": r"(?i)redis://[^@\s]+@|rediss://[^@\s]+@", "name": "Redis Connection String", "severity": "High"},
]

DISCLOSURE_ENDPOINTS = [
    "/.env", "/.git/config", "/info", "/debug", "/status",
    "/health", "/actuator", "/actuator/info", "/api/health",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/server-status", "/server-info", "/phpinfo.php",
    "/wp-json/wp/v2/users", "/.git/HEAD",
]


def detect_disclosure(response: dict, target: str = "") -> Finding | None:
    body = response.get("body", "")
    headers = response.get("headers", {})
    status = response.get("status_code", 0)

    for entry in SENSITIVE_PATTERNS:
        matches = re.findall(entry["pattern"], body)
        if matches:
            redacted = ", ".join(m[:20] + "..." for m in matches[:3])
            cvss, vector = score_finding("info_disclosure")
            severity = entry["severity"]
            return Finding(
                vulnerability=f"Information Disclosure: {entry['name']}",
                severity=severity,
                description=f"Found {len(matches)} instance(s) of '{entry['name']}' in response: {redacted}",
                target=target,
                attack_type="info_disclosure",
                payload=f"disclosure={entry['name']}",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Remove sensitive data from responses. Implement proper response sanitization.",
            )

    if status == 200 and any(p in target for p in [".env", ".git", "phpinfo"]):
        cvss, vector = score_finding("info_disclosure")
        return Finding(
            vulnerability="Sensitive Endpoint Exposed",
            severity="High",
            description=f"Sensitive file/endpoint accessible and returns HTTP 200: {target}",
            target=target,
            attack_type="info_disclosure",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Restrict access to sensitive endpoints and configuration files.",
        )

    return None


def get_sensitive_endpoints() -> list[str]:
    return list(DISCLOSURE_ENDPOINTS)
