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
            "X-XSS-Protection": "Legacy XSS filter (deprecated but still used).",
            "Referrer-Policy": "Controls referrer information leakage.",
            "Permissions-Policy": "Restricts browser feature access.",
        }
        self.sensitive_patterns = {
            "Potential API Key": re.compile(
                r'(?:key|api_key|apikey|secret|passwd|password|token|bearer)\s*[:=]\s*["\'][a-zA-Z0-9_\-\|=+]{16,40}["\']',
                re.IGNORECASE,
            ),
            "Internal Path Leak": re.compile(
                r"(?:[a-zA-Z]:\\(?:Users|Windows|Program Files)|/home/|/var/www/|/opt/|/usr/local/)\w+",
                re.IGNORECASE,
            ),
            "Email Address Leak": re.compile(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ),
            "IP Address Leak": re.compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            ),
            "AWS Key Leak": re.compile(
                r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            ),
            "JWT Token Leak": re.compile(
                r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}",
            ),
            "Cloud SQL/DB Connection String": re.compile(
                r"(?:mysql|postgres|mongodb)://[^\s]+",
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

        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header, description in self.recommended_headers.items():
            if header.lower() not in lower_headers:
                findings.append(
                    {
                        "vulnerability": f"Missing Security Header: {header}",
                        "severity": "Low",
                        "description": description,
                        "target": url,
                    }
                )

        for banner in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
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

        csp = lower_headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            findings.append(
                {
                    "vulnerability": "Weak Content-Security-Policy (unsafe-inline)",
                    "severity": "Medium",
                    "description": "CSP allows unsafe-inline scripts, reducing XSS protection.",
                    "target": url,
                }
            )
        if csp and "unsafe-eval" in csp:
            findings.append(
                {
                    "vulnerability": "Weak Content-Security-Policy (unsafe-eval)",
                    "severity": "Medium",
                    "description": "CSP allows unsafe-eval, enabling eval-based attacks.",
                    "target": url,
                }
            )

        if lower_headers.get("strict-transport-security", ""):
            hsts = lower_headers["strict-transport-security"]
            if "max-age=" in hsts:
                match = re.search(r"max-age=(\d+)", hsts)
                if match and int(match.group(1)) < 31536000:
                    findings.append(
                        {
                            "vulnerability": "Weak HSTS (less than 1 year)",
                            "severity": "Low",
                            "description": f"HSTS max-age={match.group(1)}s (< 1 year recommended).",
                            "target": url,
                        }
                    )

        if not lower_headers.get("content-type", ""):
            findings.append(
                {
                    "vulnerability": "Missing Content-Type Header",
                    "severity": "Low",
                    "description": "No Content-Type header increases MIME-sniffing risk.",
                    "target": url,
                }
            )

        for issue_name, pattern in self.sensitive_patterns.items():
            for match in pattern.findall(body):
                snippet = match if isinstance(match, str) else str(match)
                severity = "High" if issue_name in ("AWS Key Leak", "JWT Token Leak") else "Medium"
                findings.append(
                    {
                        "vulnerability": f"Sensitive Information Exposure ({issue_name})",
                        "severity": severity,
                        "description": f"Suspicious string: '{snippet[:50]}...'",
                        "target": url,
                    }
                )

        return findings
