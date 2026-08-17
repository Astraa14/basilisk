"""Cross-Origin Resource Sharing (CORS) misconfiguration detection.

Detects insecure CORS configurations that allow cross-origin attacks,
including credential exposure, subdomain bypass, and wildcard vulnerabilities.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Insecure CORS configurations
INSECURE_CONFIGURATIONS: list[dict] = [
    {
        "name": "wildcard_origin",
        "pattern": r"Access-Control-Allow-Origin:\s*\\*",
        "description": "Access-Control-Allow-Origin: * allows any origin",
        "risk": "critical",
    },
    {
        "name": "credential_with_wildcard",
        "pattern": r"Access-Control-Allow-Origin: .*" r".*Access-Control-Allow-Credentials: .*",
        "description": "Allowing credentials with wildcard origin is insecure",
        "risk": "critical",
    },
    {
        "name": "allow_credentials_origin_mismatch",
        "pattern": r"Access-Control-Allow-Origin: .*\\n\\s*Access-Control-Allow-Credentials: .*",
        "description": "Credentials allowed with mismatched origin",
        "risk": "high",
    },
    {
        "name": "exposed_headers_info",
        "pattern": r"Access-Control-Expose-Headers: .*",
        "description": "Exposing headers can reveal internal information",
        "risk": "medium",
    },
]

# Allowed methods that should be restricted
RESTRICTED_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]


def analyze_cors(
    headers: dict,
) -> dict:
    """Analyze CORS headers for misconfigurations.

    Args:
        headers: Response headers dict.

    Returns:
        dict with analysis results including misconfigurations and risk level.
    """
    findings: dict = {
        "misconfigurations": [],
        "risk_level": "info",
        "recommendations": [],
    }

    # Get the Access-Control-Allow-Origin header
    aoai = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    acae = headers.get("Access-Control-Allow-Methods", "")
    acaeh = headers.get("Access-Control-Expose-Headers", "")

    # Check for wildcard origin
    if re.search(r"\\*", aoai):
        findings["misconfigurations"].append(
            {
                "name": "wildcard_origin",
                "description": "Access-Control-Allow-Origin: * allows any origin to access "
                "the resource.",
                "evidence": f"Header value: {aoai}",
            }
        )
        findings["risk_level"] = "critical"

    # Check for credential with wildcard - insecure combination
    if re.search(r"\\*", aoai) and re.search(r"\\w+", acac, re.IGNORECASE):
        findings["misconfigurations"].append(
            {
                "name": "credential_with_wildcard",
                "description": "Allowing credentials (cookies/auth) with a wildcard origin "
                "is insecure and enables cross-origin data theft.",
                "evidence": f"Origin: {aoai}, Credentials: {acac}",
            }
        )
        findings["risk_level"] = "critical" if findings["risk_level"] != "critical" else "critical"

    # Check for overly permissive methods
    if acae:
        methods = re.findall(r"\\w+", acae)
        if any(m.upper() in RESTRICTED_METHODS for m in methods):
            # Check if all HTTP methods are allowed
            if set(methods) >= set(RESTRICTED_METHODS):
                findings["misconfigurations"].append(
                    {
                        "name": "overly_permissive_methods",
                        "description": "Access-Control-Allow-Methods allows all HTTP methods, "
                        "including potentially dangerous ones.",
                        "evidence": f"Allowed methods: {', '.join(methods)}",
                    }
                )
                findings["risk_level"] = "high" if findings["risk_level"] != "critical" else "critical"

    # Check for exposed headers
    if acaeh:
        findings["misconfigurations"].append(
            {
                "name": "exposed_headers_info",
                "description": "Access-Control-Expose-Headers allows client-side code "
                "to access headers that may contain sensitive information.",
                "evidence": f"Exposed headers: {acaeh}",
            }
        )
        if findings["risk_level"] not in ("critical", "high"):
            findings["risk_level"] = "medium"

    # Recommendations
    if any(m["name"] == "wildcard_origin" for m in findings["misconfigurations"]):
        findings["recommendations"].append(
            "Replace wildcard * with specific origin(s) instead of allowing all origins."
        )
    if any(m["name"] == "credential_with_wildcard" for m in findings["misconfigurations"]):
        findings["recommendations"].append(
            "Either restrict the origin or remove Access-Control-Allow-Credentials."
        )
    if any(m["name"] == "overly_permissive_methods" for m in findings["misconfigurations"]):
        findings["recommendations"].append(
            "Restrict Access-Control-Allow-Methods to only required HTTP methods."
        )
    if not any(m["name"] == "wildcard_origin" for m in findings["misconfigurations"]):
        findings["recommendations"].append(
            "Always specify trusted origins instead of using wildcard."
        )

    return findings


def cors_misconfiguration_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for CORS misconfigurations.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from CORS misconfiguration fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request and get all headers
    response = engine.send("GET", url, timeout=timeout)
    if not response:
        return findings

    # Analyze CORS headers
    cors_analysis = analyze_cors(response.get("headers", {}))

    for misconfig in cors_analysis["misconfigurations"]:
        risk = misconfig.get("risk", "medium")
        cvss_map = {"critical": 8.1, "high": 7.5, "medium": 6.0, "low": 4.0}
        cvss = cvss_map.get(risk, 6.0)

        findings.append(
            Finding(
                vulnerability=f"CORS misconfiguration: {misconfig['name']}",
                severity=risk,
                description=misconfig["description"],
                target=url,
                attack_type="cors_misconfig",
                cvss_score=cvss,
                cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if 'H' in risk else 'I'}/I:{'H' if 'H' in risk else 'M'}/A:{'H' if 'H' in risk else 'M'}",
                remediation=misconfig.get("recommendations", ["Review CORS configuration"])[
                    0
                ]
                if isinstance(misconfig.get("recommendations"), list)
                else misconfig.get("recommendations", ""),
            )
        )

    # If no misconfigurations found but CORS header present, log as info
    if not cors_analysis["misconfigurations"] and "Access-Control-Allow-Origin" in response.get("headers", {}):
        findings.append(
            Finding(
                vulnerability="CORS header present with no obvious misconfigurations",
                severity="Low",
                description="CORS header is present but configuration appears properly restricted.",
                target=url,
                attack_type="cors_misconfig",
                cvss_score=2.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Maintain current CORS configuration and monitor for changes.",
            )
        )

    return findings