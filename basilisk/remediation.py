"""Automatic remediation suggestion generator with OWASP mappings."""

from __future__ import annotations

from typing import Any

from basilisk.models import Finding

OWASP_TOP_10_2021: dict[str, dict] = {
    "A01": {"name": "Broken Access Control", "id": "A01:2021"},
    "A02": {"name": "Cryptographic Failures", "id": "A02:2021"},
    "A03": {"name": "Injection", "id": "A03:2021"},
    "A04": {"name": "Insecure Design", "id": "A04:2021"},
    "A05": {"name": "Security Misconfiguration", "id": "A05:2021"},
    "A06": {"name": "Vulnerable and Outdated Components", "id": "A06:2021"},
    "A07": {"name": "Identification and Authentication Failures", "id": "A07:2021"},
    "A08": {"name": "Software and Data Integrity Failures", "id": "A08:2021"},
    "A09": {"name": "Security Logging and Monitoring Failures", "id": "A09:2021"},
    "A10": {"name": "Server-Side Request Forgery (SSRF)", "id": "A10:2021"},
}

ATTACK_TO_OWASP: dict[str, str] = {
    "sqli": "A03", "blind_sqli": "A03", "xss": "A03", "dom_xss": "A03",
    "cmdi": "A03", "ssti": "A03", "ssti_advanced": "A03", "ldap": "A03",
    "nosqli": "A03", "graphql": "A03", "xxe": "A03",
    "auth_bypass": "A07", "csrf": "A07", "privilege_escalation": "A01",
    "credential_stuffing": "A07",
    "bola": "A01", "business_logic": "A04",
    "ssrf": "A10", "ssrf_oob": "A10",
    "open_redirect": "A01",
    "path_traversal": "A01", "lfi": "A01",
    "cms": "A06", "dependency_check": "A06",
    "info_disclosure": "A05", "api_enum": "A05",
    "prototype_pollution": "A08",
    "race_condition": "A04",
    "network_segmentation": "A05",
    "container_escape": "A05",
    "zero_day": "A06",
    "websocket": "A03",
    "mobile_api": "A07",
    "compliance": "A05",
    "smuggling": "A05",
    "memory_corruption": "A06",
    "payload_chain": "A08",
}

REMEDIATION_TEMPLATES: dict[str, list[str]] = {
    "sqli": [
        "Use parameterized queries / prepared statements for all database operations.",
        "Implement strict input validation using an allowlist approach.",
        "Apply the principle of least privilege to database accounts.",
        "Use an ORM that handles query parameterization automatically.",
    ],
    "xss": [
        "Contextually encode all user-supplied data before rendering.",
        "Implement Content Security Policy (CSP) as a defense-in-depth measure.",
        "Use safe DOM APIs (textContent, innerText) instead of innerHTML.",
        "Apply HTML entity encoding for HTML body context.",
    ],
    "cmdi": [
        "Avoid passing user input directly to shell commands.",
        "Use language-native APIs instead of shell execution when possible.",
        "Implement strict input validation — restrict to an allowlist of permitted values.",
        "Escape shell metacharacters if shell execution is unavoidable.",
    ],
    "ssrf": [
        "Restrict outbound network access from application servers using egress firewalls.",
        "Validate and sanitize all URLs provided by users against an allowlist.",
        "Disable HTTP redirect following for internal requests.",
        "Use a dedicated URL parser to normalize and validate URLs.",
    ],
    "ssti": [
        "Avoid rendering user input in template engines without proper sandboxing.",
        "Use template engines with auto-escaping enabled.",
        "Apply the principle of least privilege to template contexts.",
        "Consider using logic-less template engines for user-facing templates.",
    ],
    "auth_bypass": [
        "Enforce strict algorithm validation in JWT libraries.",
        "Implement server-side authorization checks on every endpoint.",
        "Use short-lived tokens with proper refresh token rotation.",
        "Never trust client-provided headers for authentication decisions.",
    ],
    "bola": [
        "Implement object-level authorization checks on every API endpoint.",
        "Use unpredictable identifiers (UUIDs) instead of sequential IDs.",
        "Verify the authenticated user has permission to access the requested resource.",
    ],
    "csrf": [
        "Implement anti-CSRF tokens for all state-changing operations.",
        "Use SameSite=Strict or SameSite=Lax cookie attribute.",
        "Validate Origin and Referer headers for sensitive operations.",
        "Require re-authentication for high-value actions.",
    ],
}

SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


class RemediationGenerator:
    """Generate OWASP-mapped remediation suggestions for findings."""

    def generate(self, finding: Finding) -> str:
        owasp_id = ATTACK_TO_OWASP.get(finding.attack_type, "A03")
        owasp = OWASP_TOP_10_2021.get(owasp_id, {"name": "Injection", "id": "A03:2021"})
        templates = REMEDIATION_TEMPLATES.get(finding.attack_type, [
            "Implement proper input validation and output encoding.",
            "Apply the principle of least privilege.",
            "Keep software dependencies up to date.",
        ])

        remediation = f"[OWASP {owasp['id']} – {owasp['name']}]\n"
        for i, step in enumerate(templates[:3], 1):
            remediation += f"  {i}. {step}\n"

        if finding.remediation:
            remediation += f"\n  {finding.remediation}"

        return remediation.strip()

    def generate_report(self, findings: list[Finding]) -> str:
        sorted_findings = sorted(
            findings,
            key=lambda f: (SEVERITY_PRIORITY.get(f.severity, 99), -f.cvss_score),
        )
        lines = ["# Remediation Report", "", "## Summary"]
        critical = sum(1 for f in sorted_findings if f.severity == "Critical")
        high = sum(1 for f in sorted_findings if f.severity == "High")
        medium = sum(1 for f in sorted_findings if f.severity == "Medium")
        low = sum(1 for f in sorted_findings if f.severity == "Low")

        lines.append(f"- Critical: {critical}")
        lines.append(f"- High: {high}")
        lines.append(f"- Medium: {medium}")
        lines.append(f"- Low: {low}")
        lines.append("")

        for f in sorted_findings:
            lines.append(f"### [{f.severity}] {f.vulnerability}")
            lines.append(f"**Target:** {f.target}")
            lines.append(f"**OWASP:** {ATTACK_TO_OWASP.get(f.attack_type, 'N/A')}")
            lines.append(f"**CVSS:** {f.cvss_score} ({f.cvss_vector})")
            lines.append("")
            lines.append(self.generate(f))
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def map_owasp(self, attack_type: str) -> str:
        owasp_id = ATTACK_TO_OWASP.get(attack_type, "A03")
        owasp = OWASP_TOP_10_2021.get(owasp_id, {"name": "Unknown", "id": "A03:2021"})
        return f"{owasp['id']} – {owasp['name']}"

    def get_top_10_summary(self, findings: list[Finding]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in findings:
            owasp_id = ATTACK_TO_OWASP.get(f.attack_type, "A03")
            owasp = OWASP_TOP_10_2021.get(owasp_id, {"name": "Other", "id": "A03:2021"})
            key = f"{owasp['id']} – {owasp['name']}"
            summary[key] = summary.get(key, 0) + 1
        return dict(sorted(summary.items(), key=lambda x: -x[1]))


def get_owasp_mapping() -> dict[str, str]:
    return dict(ATTACK_TO_OWASP)

def get_remediation_templates() -> dict[str, list[str]]:
    return dict(REMEDIATION_TEMPLATES)
