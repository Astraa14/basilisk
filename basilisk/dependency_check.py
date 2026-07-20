"""Dependency vulnerability check — identify outdated components by response fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding


@dataclass
class DependencyVuln:
    name: str
    cve: str
    severity: str
    version_pattern: str
    affected_versions: str
    description: str = ""
    remediation: str = ""


KNOWN_VULNERABLE_VERSIONS: list[DependencyVuln] = [
    DependencyVuln("jQuery", "CVE-2020-11023", "Medium", r"jquery.*(\d+\.\d+\.\d+)", "< 3.5.0", "Prototype pollution in jQuery"),
    DependencyVuln("AngularJS", "CVE-2022-25844", "High", r"angular.*(\d+\.\d+\.\d+)", "< 1.8.0", "AngularJS sandbox escape"),
    DependencyVuln("Bootstrap", "CVE-2019-8331", "Medium", r"bootstrap.*(\d+\.\d+\.\d+)", "< 4.3.1", "XSS in Bootstrap tooltip"),
    DependencyVuln("Lodash", "CVE-2021-23337", "High", r"lodash.*(\d+\.\d+\.\d+)", "< 4.17.21", "Prototype pollution in Lodash"),
    DependencyVuln("WordPress", "CVE-2024-0001", "High", r"wordpress.*(\d+\.\d+\.\d+)", "< 6.4.0", "WordPress core vulnerabilities"),
    DependencyVuln("Drupal", "CVE-2019-6340", "Critical", r"drupal.*(\d+\.\d+\.\d+)", "< 8.6.10", "Drupal RCE"),
    DependencyVuln("PHP", "CVE-2024-4577", "Critical", r"php/(\d+\.\d+\.\d+)", "< 8.3.8", "PHP CGI RCE"),
    DependencyVuln("Apache", "CVE-2021-41773", "Critical", r"Apache/(\d+\.\d+\.\d+)", "< 2.4.50", "Apache path traversal RCE"),
    DependencyVuln("Nginx", "CVE-2021-23017", "Medium", r"nginx/(\d+\.\d+\.\d+)", "< 1.21.0", "Nginx DNS resolution DoS"),
    DependencyVuln("OpenSSL", "CVE-2022-3602", "High", r"OpenSSL/(\d+\.\d+\.\d+)", "< 3.0.7", "OpenSSL buffer overflow"),
    DependencyVuln("IIS", "CVE-2021-31166", "Critical", r"Microsoft-IIS/(\d+\.\d+)", "< 10.0", "IIS HTTP Protocol Stack RCE"),
]

SERVER_HEADER_PATTERN = re.compile(r"(\w[\w.-]+)/(\d+\.\d+(?:\.\d+)?)")
VERSION_PATTERN = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _parse_version(version_str: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version_str.split("."))
    except (ValueError, AttributeError):
        return (0,)


def _version_less_than(v1: str, v2: str) -> bool:
    return _parse_version(v1) < _parse_version(v2)


def check_dependency_vulns(
    headers: dict[str, str] | None,
    body: str = "",
    target: str = "",
) -> list[Finding]:
    """Check response headers and body for known vulnerable dependency versions."""
    findings: list[Finding] = []
    if not headers:
        headers = {}
    lower_body = body.lower() if body else ""

    # Check server header
    server = headers.get("Server", headers.get("server", ""))
    if server:
        match = SERVER_HEADER_PATTERN.search(server)
        if match:
            product = match.group(1)
            version = match.group(2)
            for vuln in KNOWN_VULNERABLE_VERSIONS:
                if vuln.name.lower() in product.lower():
                    if _version_less_than(version, vuln.affected_versions.split(" ")[-1].lstrip("<")):
                        cvss, vector = score_finding("dependency_check")
                        findings.append(
                            Finding(
                                vulnerability=f"Vulnerable Dependency: {vuln.name}",
                                severity=vuln.severity,
                                description=f"{vuln.description}. Detected: {product} {version}. Affected: {vuln.affected_versions}. CVE: {vuln.cve}.",
                                target=target,
                                attack_type="dependency_check",
                                cvss_score=cvss,
                                cvss_vector=vector,
                                remediation=vuln.remediation or f"Upgrade {vuln.name} to a patched version.",
                                references=[f"https://nvd.nist.gov/vuln/detail/{vuln.cve}"],
                            )
                        )
                    break

    # Check for version strings in HTML/JS body
    for vuln in KNOWN_VULNERABLE_VERSIONS:
        match = re.search(vuln.version_pattern, lower_body)
        if match:
            version = match.group(1)
            affected = vuln.affected_versions.split(" ")[-1].lstrip("<").lstrip("=")
            if _version_less_than(version, affected):
                cvss, vector = score_finding("dependency_check")
                findings.append(
                    Finding(
                        vulnerability=f"Vulnerable Dependency: {vuln.name}",
                        severity=vuln.severity,
                        description=f"{vuln.description} (CVE: {vuln.cve}). Detected: v{version}. Affected: {vuln.affected_versions}.",
                        target=target,
                        attack_type="dependency_check",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation=f"Upgrade {vuln.name} to version {affected} or later.",
                        references=[f"https://nvd.nist.gov/vuln/detail/{vuln.cve}"],
                    )
                )

    return findings


def get_known_vulns() -> list[DependencyVuln]:
    return list(KNOWN_VULNERABLE_VERSIONS)
