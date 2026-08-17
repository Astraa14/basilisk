"""Subresource Integrity (SRI) bypass detection.

Detects situations where SRI can be bypassed, allowing unauthorized scripts
to be loaded from third-party resources.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Common SRI bypass techniques
SRI_BYPASS_TECHNIQUES: list[dict] = [
    {
        "name": "cross-origin-resource-sharing",
        "description": "CORS misconfiguration allows loading resources "
        "without valid SRI hashes",
        "pattern": r"Access-Control-Allow-Origin: .*",
    },
    {
        "name": "subresource_type confusion",
        "description": "Mismatched type attribute allows resource loading",
        "pattern": r'type="([^"]+)"\\s+integrity',
    },
    {
        "name": "dynamic-import-bypass",
        "description": "Using dynamic import() to load scripts without SRI",
        "pattern": r"import\\(['\"]",
    },
    {
        "name": "worker-import-bypass",
        "description": "Using service worker import to bypass page-level SRI",
        "pattern": r"importScripts\\s*\\(",
    },
]


def analyze_sri(
    html: str,
    headers: dict,
) -> dict:
    """Analyze HTML for SRI presence and bypass vectors.

    Args:
        html: HTML content to analyze.
        headers: Response headers.

    Returns:
        dict with SRI analysis results.
    """
    result: dict = {
        "has_sri": False,
        "sri_hashes": [],
        "bypasses": [],
        "risk_level": "info",
    }

    # Check for SRI in script tags
    sri_pattern = r'integrity="([^"]+)"'
    sri_matches = re.findall(sri_pattern, html)

    if sri_matches:
        result["has_sri"] = True
        result["sri_hashes"] = sri_matches

    # Check for bypass techniques
    html_lower = html.lower()
    for bypass in SRI_BYPASS_TECHNIQUES:
        if re.search(bypass["pattern"], html_lower, re.IGNORECASE):
            result["bypasses"].append(bypass["description"])
            result["risk_level"] = "high" if result["risk_level"] != "high" else "high"

    # Check CORS header interaction
    aoai = headers.get("Access-Control-Allow-Origin", "")
    if aoai and not result["has_sri"]:
        result["bypasses"].append(
            "CORS misconfiguration may allow loading resources without valid SRI"
        )
        result["risk_level"] = "high"

    return result


def sri_bypass_fuzzer(
    html: str,
    headers: dict,
) -> list[Finding]:
    """Fuzz HTML for SRI bypass detection.

    Args:
        html: HTML content to analyze.
        headers: Response headers.

    Returns:
        List of Findings from SRI bypass fuzzing.
    """
    from basilisk.models import Finding

    findings: list[Finding] = []

    analysis = analyze_sri(html, headers)

    if not analysis["has_sri"]:
        findings.append(
            Finding(
                vulnerability="No Subresource Integrity detected",
                severity="Medium",
                description="No Subresource Integrity hashes found in page scripts. "
                "External resources can be loaded without integrity verification.",
                target="page",
                attack_type="sri_bypass",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Add integrity hashes to all external script and stylesheet "
                "references. Use hashes rather than algorithms for better security.",
            )
        )
    else:
        # SRI is present, check for bypass vectors
        if analysis["bypasses"]:
            findings.append(
                Finding(
                    vulnerability="SRI bypass techniques detected",
                    severity="Medium",
                    description=f"SRI bypass techniques possible: {'; '.join(analysis['bypasses'])}",
                    target="page",
                    attack_type="sri_bypass",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    remediation="Harden SRI implementation. Use hash-based integrity "
                    "checks rather than algorithm-based, and ensure CORS is properly "
                    "configured when using external resources.",
                )
            )
        else:
            findings.append(
                Finding(
                    vulnerability="SRI properly implemented",
                    severity="Info",
                    description="SRI hashes present with no detected bypass vectors.",
                    target="page",
                    attack_type="sri_bypass",
                    cvss_score=2.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    remediation="Maintain current SRI implementation and monitor "
                    "for new bypass techniques.",
                )
            )

    return findings