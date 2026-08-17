"""CSP analysis - Content-Security-Policy analysis and bypass detection.

Analyzes CSP headers for misconfigurations and identifies bypass vectors.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# CSP directives
CSP_DIRECTIVES: list[str] = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "frame-src",
    "sandbox",
    "form-action",
    "frame-ancestors",
]

# Common CSP bypass techniques
CSP_BYPASS_TECHNIQUES: list[dict] = [
    {
        "name": "unsafe-inline",
        "description": "Allowing unsafe-inline enables inline scripts/styles",
        "risk": "critical",
    },
    {
        "name": "unsafe-eval",
        "description": "Allowing unsafe-eval enables eval() calls",
        "risk": "high",
    },
    {
        "name": "wildcard-domain",
        "description": "Using wildcard domains (*.example.com) is less secure",
        "risk": "medium",
    },
]


def analyze_csp(
    csp_header: str,
) -> dict:
    """Analyze a Content-Security-Policy header.

    Args:
        csp_header: The Content-Security-Policy header value.

    Returns:
        dict with CSP analysis results including directives and strength.
    """
    result: dict = {
        "directives": {},
        "strength": "unknown",
    }

    if not csp_header:
        result["strength"] = "none"
        return result

    # Parse directives from the CSP header
    # CSP format: default-src 'self'; script-src 'self' https://cdn.example.com;
    # We'll parse semi-colon separated directives
    directives_str = csp_header.split(";")
    
    for part in directives_str:
        part = part.strip()
        if not part:
            continue

        # Handle directive with specified sources
        if " " in part:
            directive, value = part.split(" ", 1)
            directives[directive.strip().lower()] = value.strip()
        else:
            # Directive without sources (e.g., 'unsafe-inline')
            directives[part.strip().lower()] = ""

    # Determine strength based on presence of restrictive directives
    has_restrictive = any(
        d in directives and directives[d] not in ("none", "self", "strict-origin-when-cross-origin")
        for d in ["default-src", "script-src", "style-src", "img-src", "connect-src"])

    has_unsafe_inline = "unsafe-inline" in directives
    has_unsafe_eval = "unsafe-eval" in directives

    if not has_restrictive and not has_unsafe_inline and not has_unsafe_eval:
        result["strength"] = "strong"
    elif has_unsafe_inline or has_unsafe_eval:
        result["strength"] = "permissive"
    elif not has_restrictive:
        result["strength"] = "limited"
    else:
        result["strength"] = "moderate"

    return result


def csp_analysis_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for CSP analysis.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from CSP analysis fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request and get CSP header
    response = engine.send("GET", url, timeout=timeout)
    if not response:
        return findings

    csp_header = response.get("headers", {}).get("Content-Security-Policy", "")
    analysis = analyze_csp(csp_header)

    if analysis["strength"] == "none":
        # No CSP header
        findings.append(
            Finding(
                vulnerability="Missing Content-Security-Policy header",
                severity="Critical",
                description="No Content-Security-Policy header detected. "
                "This leaves the application vulnerable to XSS attacks.",
                target=url,
                attack_type="csp_analysis",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                remediation="Implement a strict Content-Security-Policy header on all "
                "responses. Start with a policy that restricts sources and gradually "
                "relax as needed.",
            )
        )
    elif analysis["strength"] == "permissive":
        # Check for specific bypass vectors
        bypass_descriptions: list[str] = []
        for bypass in CSP_BYPASS_TECHNIQUES:
            if bypass["name"] == "unsafe-inline" and "unsafe-inline" in analysis.get("directives", {}):
                bypass_descriptions.append(bypass["description"])
            elif bypass["name"] == "unsafe-eval" and "unsafe-eval" in analysis.get("directives", {}):
                bypass_descriptions.append(bypass["description"])
            elif bypass["name"] == "wildcard-domain":
                # Check for wildcard patterns in directives
                for dir_name, dir_value in analysis.get("directives", {}).items():
                    if re.search(r"\*\.", dir_value or ""):
                        bypass_descriptions.append(
                            f"Wildcard domain in {dir_name}: {dir_value}"
                        )

        if bypass_descriptions:
            findings.append(
                Finding(
                    vulnerability="CSP bypass vectors detected",
                    severity="High",
                    description=f"CSP present but contains bypass vectors: "
                    f"{'; '.join(bypass_descriptions)}",
                    target=url,
                    attack_type="csp_analysis",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    remediation="Remove unsafe-inline and unsafe-eval from CSP. "
                    "Use strict source restrictions rather than wildcards.",
                )
            )
        else:
            findings.append(
                Finding(
                    vulnerability="CSP header present but overly permissive",
                    severity="High",
                    description="CSP header present but contains too few directives "
                    "to be effective.",
                    target=url,
                    attack_type="csp_analysis",
                    cvss_score=7.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    remediation="Add restrictive CSP directives (default-src 'self', "
                    "script-src 'self', style-src 'self') and remove unsafe-inline "
                    "and unsafe-eval.",
                )
            )
    else:
        # CSP present with some restrictions
        findings.append(
            Finding(
                vulnerability="Content-Security-Policy analysis",
                severity="Info",
                description="Content-Security-Policy header present with some restrictions. "
                f"Strength: {analysis['strength']}.",
                target=url,
                attack_type="csp_analysis",
                cvss_score=2.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Review CSP policy and ensure all sources are properly "
                "restricted. Consider adding missing directives for complete coverage.",
            )
        )

    return findings