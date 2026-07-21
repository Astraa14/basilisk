"""Automatic bug bounty report generation with fix recommendations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from basilisk.models import Finding, ScanReport
from basilisk.remediation import RemediationGenerator

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class BountyReport:
    title: str = ""
    summary: str = ""
    severity_summary: str = ""
    total_findings: int = 0
    target: str = ""
    scope: list[str] = field(default_factory=list)
    findings_sections: list[dict] = field(default_factory=list)
    recommendations: str = ""
    raw_markdown: str = ""


class BountyReportGenerator:
    """Generate professional bug bounty reports in multiple formats."""

    def __init__(self, researcher_name: str = "Basilisk Scanner"):
        self.researcher_name = researcher_name
        self._remediation = RemediationGenerator()

    def generate_markdown(self, scan_result: dict) -> str:
        findings = [Finding(**f) if isinstance(f, dict) else f for f in scan_result.get("findings", [])]
        target = scan_result.get("target", "unknown")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        severity_counts = self._count_severities(findings)

        lines = []
        lines.append(f"# Security Assessment Report: {target}")
        lines.append("")
        lines.append(f"**Researcher:** {self.researcher_name}")
        lines.append(f"**Date:** {now}")
        lines.append(f"**Tool:** Basilisk v2.0 Web Vulnerability Scanner")
        lines.append(f"**Mode:** {scan_result.get('mode', 'static')}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"Total findings: **{len(findings)}**")
        lines.append(f"- Critical: **{severity_counts['Critical']}**")
        lines.append(f"- High: **{severity_counts['High']}**")
        lines.append(f"- Medium: **{severity_counts['Medium']}**")
        lines.append(f"- Low: **{severity_counts['Low']}**")
        lines.append(f"- Info: **{severity_counts['Info']}**")
        lines.append("")
        lines.append(f"Pages scanned: {scan_result.get('pages_scanned', 0)}")
        lines.append(f"Forms found: {scan_result.get('forms_found', 0)}")
        lines.append(f"Vulnerable: {'Yes' if scan_result.get('vulnerable') else 'No'}")
        lines.append("")

        if not findings:
            lines.append("## Findings")
            lines.append("")
            lines.append("No vulnerabilities were detected during the scan.")
            lines.append("")
            lines.append("---")
            lines.append("")
            return "\n".join(lines)

        sorted_findings = sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.cvss_score),
        )

        lines.append("## Vulnerability Details")
        lines.append("")

        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"### {i}. [{f.severity}] {f.vulnerability}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Target** | `{f.target}` |")
            lines.append(f"| **Type** | `{f.attack_type}` |")
            lines.append(f"| **CVSS Score** | {f.cvss_score} |")
            lines.append(f"| **CVSS Vector** | `{f.cvss_vector}` |")
            lines.append(f"| **Confidence** | {f.confidence * 100:.0f}% |")
            if f.payload:
                lines.append(f"| **Payload** | `{f.payload[:100]}` |")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(self._remediation.generate(f))
            lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("## OWASP Top 10 Breakdown")
        lines.append("")
        owasp_summary = self._remediation.get_top_10_summary(findings)
        for key, count in owasp_summary.items():
            bars = "█" * min(count, 20)
            lines.append(f"- {key}: {count} {bars}")
        lines.append("")

        lines.append("*Report generated automatically by Basilisk v2.0*")
        lines.append("")

        return "\n".join(lines)

    def generate_json(self, scan_result: dict) -> str:
        return json.dumps({
            "report": {
                "generator": self.researcher_name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": "Basilisk v2.0",
                "scan": {
                    "target": scan_result.get("target"),
                    "mode": scan_result.get("mode"),
                    "pages_scanned": scan_result.get("pages_scanned"),
                    "forms_found": scan_result.get("forms_found"),
                },
                "summary": self._count_severities(
                    [Finding(**f) if isinstance(f, dict) else f for f in scan_result.get("findings", [])]
                ),
                "findings": [
                    {
                        "vulnerability": f.vulnerability,
                        "severity": f.severity,
                        "cvss_score": f.cvss_score,
                        "cvss_vector": f.cvss_vector,
                        "target": f.target,
                        "attack_type": f.attack_type,
                        "description": f.description,
                        "payload": f.payload[:100] if f.payload else "",
                        "remediation": self._remediation.generate(f),
                    }
                    for f in ([Finding(**f) if isinstance(f, dict) else f for f in scan_result.get("findings", [])])
                ],
            }
        }, indent=2)

    def generate_short_summary(self, scan_result: dict) -> str:
        findings = scan_result.get("findings", [])
        if findings and isinstance(findings[0], dict):
            finding_objs = [Finding(**f) for f in findings]
        else:
            finding_objs = findings

        severity_counts = self._count_severities(finding_objs)
        target = scan_result.get("target", "")

        lines = [
            f"## Scan Summary: {target}",
            f"**Findings:** {len(finding_objs)} total | "
            f"Critical: {severity_counts['Critical']} | "
            f"High: {severity_counts['High']} | "
            f"Medium: {severity_counts['Medium']} | "
            f"Low: {severity_counts['Low']}",
        ]

        if finding_objs:
            sorted_f = sorted(
                finding_objs,
                key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.cvss_score),
            )
            for f in sorted_f[:5]:
                lines.append(f"- [{f.severity}] {f.vulnerability} on `{f.target[:60]}`")

        return "\n".join(lines)

    def _count_severities(self, findings: list[Finding]) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def format_report(scan_result: dict, format: str = "markdown") -> str:
    gen = BountyReportGenerator()
    if format == "json":
        return gen.generate_json(scan_result)
    elif format == "summary":
        return gen.generate_short_summary(scan_result)
    return gen.generate_markdown(scan_result)
