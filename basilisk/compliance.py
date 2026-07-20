"""Compliance checking — GDPR, HIPAA, PCI-DSS, and SOC2 security requirements."""

from __future__ import annotations

import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


COMPLIANCE_CHECKS: dict[str, list[dict]] = {
    "GDPR": [
        {"id": "GDPR-1", "name": "Privacy Policy Presence", "check": "privacy_policy", "severity": "Medium"},
        {"id": "GDPR-2", "name": "Cookie Consent", "check": "cookie_consent", "severity": "Medium"},
        {"id": "GDPR-3", "name": "Data Export Endpoint", "check": "data_export", "severity": "Low"},
        {"id": "GDPR-4", "name": "Account Deletion", "check": "account_deletion", "severity": "Low"},
        {"id": "GDPR-5", "name": "Encrypted Transport", "check": "https_only", "severity": "High"},
    ],
    "HIPAA": [
        {"id": "HIPAA-1", "name": "Encrypted Transport", "check": "https_only", "severity": "Critical"},
        {"id": "HIPAA-2", "name": "No PHI in URLs", "check": "phi_in_url", "severity": "High"},
        {"id": "HIPAA-3", "name": "No PHI in Responses", "check": "phi_in_response", "severity": "High"},
        {"id": "HIPAA-4", "name": "Secure Headers", "check": "security_headers", "severity": "Medium"},
    ],
    "PCI_DSS": [
        {"id": "PCI-1", "name": "Encrypted Transport", "check": "https_only", "severity": "Critical"},
        {"id": "PCI-2", "name": "No Card Data in URLs", "check": "card_in_url", "severity": "Critical"},
        {"id": "PCI-3", "name": "No Card Data in Logs", "check": "card_in_response", "severity": "Critical"},
        {"id": "PCI-4", "name": "Secure Headers", "check": "security_headers", "severity": "Medium"},
    ],
    "SOC2": [
        {"id": "SOC2-1", "name": "Encrypted Transport", "check": "https_only", "severity": "High"},
        {"id": "SOC2-2", "name": "Security Headers", "check": "security_headers", "severity": "Medium"},
        {"id": "SOC2-3", "name": "Access Controls", "check": "auth_required", "severity": "High"},
    ],
}

PHI_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b\d{9}\b",  # MRN-like
    r"\bpatient.*id["\s:=]+[\w-]{4,}",  # Patient IDs
]

CARD_PATTERNS = [
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Basic credit card
    r"\b\d{4}[- ]?\d{6}[- ]?\d{5}\b",  # AMEX
]

COOKIE_CONSENT_PATTERNS = [
    "cookie", "cookies", "cookie consent", "cookie policy",
    "cookie notice", "accept cookies", "gdpr",
]

PRIVACY_POLICY_PATTERNS = [
    "privacy policy", "privacy notice", "data protection",
    "how we use your data", "personal data",
]


class ComplianceChecker:
    """Check a target against compliance framework requirements."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def check_gdpr(self, responses: list[dict]) -> list[Finding]:
        return self._run_checks("GDPR", responses)

    def check_hipaa(self, responses: list[dict]) -> list[Finding]:
        return self._run_checks("HIPAA", responses)

    def check_pci_dss(self, responses: list[dict]) -> list[Finding]:
        return self._run_checks("PCI_DSS", responses)

    def check_all(self, responses: list[dict]) -> dict[str, list[Finding]]:
        return {
            "gdpr": self.check_gdpr(responses),
            "hipaa": self.check_hipaa(responses),
            "pci_dss": self.check_pci_dss(responses),
            "soc2": self._run_checks("SOC2", responses),
        }

    def _run_checks(self, framework: str, responses: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        checks = COMPLIANCE_CHECKS.get(framework, [])

        combined_body = " ".join(r.get("body", "") for r in responses)
        combined_headers: dict = {}
        for r in responses:
            combined_headers.update(r.get("headers", {}))
        combined_urls = " ".join(r.get("url", "") for r in responses)

        for check in checks:
            finding = self._evaluate_check(check, combined_body, combined_headers, combined_urls)
            if finding:
                findings.append(finding)

        return findings

    def _evaluate_check(
        self, check: dict, body: str, headers: dict, urls: str
    ) -> Finding | None:
        check_name = check["check"]
        lower_body = body.lower()

        if check_name == "https_only":
            if not self.target_url.startswith("https://"):
                cvss, vector = score_finding("compliance")
                return Finding(
                    vulnerability=f"Compliance: {check['name']} ({check['id']})",
                    severity=check["severity"],
                    description=f"Target does not use HTTPS. Required by {check['id']}.",
                    target=self.target_url,
                    attack_type="compliance",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Enforce HTTPS with valid TLS certificate. Redirect all HTTP to HTTPS.",
                )

        elif check_name == "cookie_consent":
            if not any(p in lower_body for p in COOKIE_CONSENT_PATTERNS):
                cvss, vector = score_finding("compliance")
                return Finding(
                    vulnerability=f"Compliance: {check['name']} ({check['id']})",
                    severity=check["severity"],
                    description="No cookie consent banner detected. GDPR requires explicit consent for non-essential cookies.",
                    target=self.target_url,
                    attack_type="compliance",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Implement a cookie consent banner with granular opt-in/opt-out controls.",
                )

        elif check_name == "privacy_policy":
            if not any(p in lower_body for p in PRIVACY_POLICY_PATTERNS):
                cvss, vector = score_finding("compliance")
                return Finding(
                    vulnerability=f"Compliance: {check['name']} ({check['id']})",
                    severity=check["severity"],
                    description="No privacy policy link detected. GDPR requires a clear privacy policy.",
                    target=self.target_url,
                    attack_type="compliance",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Add a visible privacy policy link to all pages.",
                )

        elif check_name == "phi_in_response":
            for pattern in PHI_PATTERNS:
                if re.search(pattern, body):
                    cvss, vector = score_finding("compliance")
                    return Finding(
                        vulnerability=f"Compliance: {check['name']} ({check['id']})",
                        severity=check["severity"],
                        description="PHI (Protected Health Information) detected in response body. HIPAA violation risk.",
                        target=self.target_url,
                        attack_type="compliance",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Remove or mask PHI from application responses. Implement data classification controls.",
                    )

        elif check_name == "card_in_response":
            for pattern in CARD_PATTERNS:
                if re.search(pattern, body):
                    cvss, vector = score_finding("compliance")
                    return Finding(
                        vulnerability=f"Compliance: {check['name']} ({check['id']})",
                        severity=check["severity"],
                        description="Credit card number pattern detected in response. PCI-DSS violation.",
                        target=self.target_url,
                        attack_type="compliance",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Never display full PAN. Mask card numbers and use tokenization.",
                    )

        elif check_name == "security_headers":
            missing: list[str] = []
            if "Strict-Transport-Security" not in headers:
                missing.append("Strict-Transport-Security")
            if "Content-Security-Policy" not in headers:
                missing.append("Content-Security-Policy")
            if "X-Content-Type-Options" not in headers:
                missing.append("X-Content-Type-Options")
            if missing:
                cvss, vector = score_finding("compliance")
                return Finding(
                    vulnerability=f"Compliance: {check['name']} ({check['id']})",
                    severity=check["severity"],
                    description=f"Missing security headers: {', '.join(missing)}. Required by {check['id']}.",
                    target=self.target_url,
                    attack_type="compliance",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Implement recommended security headers: HSTS, CSP, X-Content-Type-Options.",
                )

        return None


def get_compliance_frameworks() -> list[str]:
    return list(COMPLIANCE_CHECKS.keys())
