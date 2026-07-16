"""Passive security audits (headers, banners, secret leaks)."""

from __future__ import annotations

import re


class PassiveAnalyzer:
    def __init__(self):
        self.recommended_headers = {
            "X-Frame-Options": "Protects against clickjacking.",
            "X-Content-Type-Options": "Prevents MIME-sniffing.",
            "Strict-Transport-Security": "Enforces HTTPS (HSTS).",
            "Content-Security-Policy": "Restricts resource origins.",
        }
        self.sensitive_patterns = {
            "Potential API Key": re.compile(
                r'(?:key|api_key|apikey|secret|passwd|password)\s*[:=]\s*["\'][a-zA-Z0-9_\-\|=+]{16,40}["\']',
                re.IGNORECASE,
            ),
            "Internal Path Leak": re.compile(
                r"(?:[a-zA-Z]:\\(?:Users|Windows|Program Files)|/home/|/var/www/)\w+",
                re.IGNORECASE,
            ),
        }

    def analyze(self, response_data: dict | None) -> list[dict]:
        if not response_data:
            return []

        findings: list[dict] = []
        headers = response_data.get("headers", {})
        body = response_data.get("body", "")
        url = response_data.get("url", "")

        for header, description in self.recommended_headers.items():
            if not any(h.lower() == header.lower() for h in headers):
                findings.append(
                    {
                        "vulnerability": f"Missing Security Header: {header}",
                        "severity": "Low",
                        "description": description,
                        "target": url,
                    }
                )

        for banner in ("Server", "X-Powered-By"):
            matched = next((k for k in headers if k.lower() == banner.lower()), None)
            if matched and any(c.isdigit() for c in headers[matched]):
                findings.append(
                    {
                        "vulnerability": f"Information Disclosure via '{banner}' Header",
                        "severity": "Low",
                        "description": f"Leaked version details: '{headers[matched]}'.",
                        "target": url,
                    }
                )

        for issue_name, pattern in self.sensitive_patterns.items():
            for match in pattern.findall(body):
                snippet = match if isinstance(match, str) else str(match)
                findings.append(
                    {
                        "vulnerability": f"Sensitive Information Exposure ({issue_name})",
                        "severity": "Medium",
                        "description": f"Suspicious string: '{snippet[:50]}...'",
                        "target": url,
                    }
                )

        return findings
