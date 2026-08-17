"""Cache-Control header analysis.

Analyzes Cache-Control headers for misconfigurations, caching vulnerabilities,
and improper resource caching that can lead to security issues.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Common Cache-Control directives
CACHE_DIRECTIVES: list[str] = [
    "public",
    "private",
    "no-cache",
    "no-store",
    "max-age",
    "s-maxage",
    "must-revalidate",
    "proxy-revalidate",
    "max-stale",
    "min-fresh",
    "must-understand",
]

# Insecure caching patterns
INSECURE_CACHE_PATTERNS: list[dict] = [
    {
        "name": "no_cache_no_store_missing",
        "description": "No caching directives when sensitive data is present",
        "pattern": r"no-cache.*no-store",
        "risk": "high",
    },
    {
        "name": "public_sensitive",
        "description": "Public caching of sensitive resources",
        "pattern": r"public\s-.*(password|credit|ssn|token|auth)",
        "risk": "high",
    },
    {
        "name": "short_max_age",
        "description": "Very short max-age allowing frequent revalidation",
        "pattern": r"max-age=\s*\d{1,2}",
        "risk": "medium",
    },
]

# Safe caching patterns
SAFE_CACHE_PATTERNS: list[dict] = [
    {
        "name": "secure_ecommerce",
        "description": "Recommended for e-commerce checkout pages",
        "directives": ["no-store", "private"],
    },
    {
        "name": "static_assets",
        "description": "Recommended for static assets like images, CSS, JS",
        "directives": ["public", "max-age=31536000"],
    },
]


def analyze_cache_control(
    cache_control: str,
) -> dict:
    """Analyze a Cache-Control header value.

    Args:
        cache_control: The Cache-Control header value.

    Returns:
        dict with analysis results including directives, risk level, and recommendations.
    """
    if not cache_control:
        return {
            "directives": [],
            "risk_level": "info",
            "reasons": [],
            "recommendations": [
                "Add Cache-Control headers to control caching behavior"
            ],
        }

    # Parse directives
    directives = [d.strip() for d in cache_control.split(",") if d.strip()]
    directives_lower = [d.lower() for d in directives]

    # Determine risk level
    risk_level = "low"
    risk_reasons: list[str] = []

    # Check for insecure combinations
    has_no_cache = "no-cache" in directives_lower
    has_no_store = "no-store" in directives_lower
    has_public = "public" in directives_lower

    # no-cache with no-store is insecure
    if has_no_cache and has_no_store:
        risk_level = "high"
        risk_reasons.append(
            "Both no-cache and no-store directives present, which is redundant"
        )

    # Public caching with sensitive indicators
    if has_public:
        risk_level = "medium"
        risk_reasons.append("Public caching may expose resources to intermediate proxies")

    # Very short max-age
    max_age_matches = re.findall(r"max-age=(\d+)", cache_control)
    if max_age_matches:
        max_age = int(max_age_matches[0])
        if max_age < 60:
            risk_level = "high"
            risk_reasons.append(f"Very short max-age ({max_age}s) allows frequent revalidation")
        elif max_age < 3600:
            if risk_level != "high":
                risk_level = "medium"
                risk_reasons.append(f"Short max-age ({max_age}s)")

    # Build result
    result: dict = {
        "directives": directives,
        "risk_level": risk_level,
        "reasons": risk_reasons,
        "recommendations": [],
    }

    # Generate recommendations based on findings
    if "no-store" in directives_lower:
        result["recommendations"].append(
            "Consider using 'private' instead of 'no-store' for better caching "
            "while still protecting sensitive content"
        )
    if "public" in directives_lower and risk_level in ("high", "medium"):
        result["recommendations"].append(
            "Ensure publicy-cached resources do not contain sensitive information"
        )
    if not any(d.lower() == "max-age" for d in directives_lower):
        result["recommendations"].append(
            "Add max-age directive to control caching duration"
        )
    if risk_level == "info":
        result["recommendations"].append(
            "No critical caching issues detected. Monitor for changes."
        )

    return result


def cache_control_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for Cache-Control misconfigurations.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from Cache-Control analysis fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request and get Cache-Control header
    response = engine.send("GET", url, timeout=timeout)
    if not response:
        return findings

    cache_control = response.get("headers", {}).get("Cache-Control", "")
    analysis = analyze_cache_control(cache_control)

    if not analysis["directives"]:
        # No Cache-Control header
        findings.append(
            Finding(
                vulnerability="Missing Cache-Control header",
                severity="Medium",
                description="No Cache-Control header detected. "
                "This leaves caching decisions to the default, which may not be "
                "appropriate for the resource.",
                target=url,
                attack_type="cache_control",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Add appropriate Cache-Control headers to all responses. "
                "Use 'no-store' for sensitive content, 'public' with max-age for "
                "static assets, and 'private' for user-specific content.",
            )
        )
    elif analysis["risk_level"] == "high":
        cvss, vector = 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H"
        findings.append(
            Finding(
                vulnerability="Insecure Cache-Control configuration",
                severity="High",
                description=f"Insecure Cache-Control configuration: {'; '.join(analysis['reasons'])}",
                target=url,
                attack_type="cache_control",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation=analysis["recommendations"][0]
                if analysis["recommendations"]
                else "Review and strengthen Cache-Control configuration.",
            )
        )
    elif analysis["risk_level"] == "medium":
        cvss, vector = 6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:M"
        findings.append(
            Finding(
                vulnerability="Suboptimal Cache-Control configuration",
                severity="Medium",
                description=f"Suboptimal Cache-Control configuration: {'; '.join(analysis['reasons'])}",
                target=url,
                attack_type="cache_control",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation=analysis["recommendations"][0]
                if analysis["recommendations"]
                else "Review and optimize Cache-Control configuration.",
            )
        )
    else:
        # Low risk - informational
        findings.append(
            Finding(
                vulnerability="Cache-Control header analysis",
                severity="Info",
                description="Cache-Control header present and appears properly configured.",
                target=url,
                attack_type="cache_control",
                cvss_score=1.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Maintain current Cache-Control configuration.",
            )
        )

    return findings