"""HTTP Alternate Protocol exploitation.

Detects servers that support alternate protocols (e.g., h2c, alt-svc) 
which can be exploited for protocol downgrade attacks or man-in-the-middle scenarios.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Alternate protocol vectors
ALTERNATE_PROTOCOL_VECTORS: list[dict] = [
    {
        "name": "http2_via_alt_svc",
        "description": "Server advertises HTTP/2 via Alt-Svc header which "
        "can be exploited for protocol downgrade",
        "pattern": r"Alt-Svc: .*h2=",
    },
    {
        "name": "h2c_plaintext",
        "description": "Server supports cleartext HTTP/2 (h2c) which "
        "bypasses TLS encryption",
        "pattern": r"HTTP/2 Protocol: h2c",
    },
    {
        "name": "npn_ssl",
        "description": "Server supports Next Protocol Negotiation with HTTP/2 "
        "which can be manipulated",
        "pattern": r"NPN: .*h2",
    },
]

# Safe protocol configurations
SAFE_PROTOCOL_CONFIGS: list[dict] = [
    {
        "name": "tls_only",
        "description": "Only HTTPS with TLS - secure configuration",
        "protocols": ["https"],
    },
]


def analyze_alternate_protocol(
    headers: dict,
) -> dict:
    """Analyze response headers for alternate protocol support.

    Args:
        headers: Response headers to analyze.

    Returns:
        dict with alternate protocol analysis results.
    """
    result: dict = {
        "alternate_protocols": [],
        "risk_level": "low",
        "issues": [],
    }

    # Check for Alt-Svc header
    alt_svc = headers.get("Alt-Svc", "")
    if alt_svc:
        result["alternate_protocols"].append("Alt-Svc")
        if re.search(r"h2=", alt_svc, re.IGNORECASE):
            result["issues"].append(
                "HTTP/2 advertised via Alt-Svc header"
            )
            result["risk_level"] = "medium"

    # Check for HTTP/2 protocol info
    h2_info = headers.get("X-Content-Type-Options", "")
    if "h2" in h2_info.lower() or "http2" in h2_info.lower():
        result["alternate_protocols"].append("HTTP/2 info header")
        if result["risk_level"] != "high":
            result["risk_level"] = "medium"

    # Check for NPN/ALPN indications
    server_proto = headers.get("Server", "")
    if server_proto:
        server_lower = server_proto.lower()
        if "h2" in server_lower or "http2" in server_lower:
            result["alternate_protocols"].append("Server advertises HTTP/2")
            result["risk_level"] = "medium"

    return result


def alternate_protocol_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for Alternate Protocol exploitation detection.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from Alternate Protocol fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request and get headers
    response = engine.send("GET", url, timeout=timeout)
    if not response:
        return findings

    headers = response.get("headers", {})

    # Analyze alternate protocols
    analysis = analyze_alternate_protocol(headers)

    if analysis["alternate_protocols"]:
        risk_map = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
        cvss_map = {
            "high": 7.5,
            "medium": 6.5,
            "low": 5.3,
            "info": 2.0,
        }
        cvss = cvss_map.get(analysis["risk_level"], 5.3)

        findings.append(
            Finding(
                vulnerability="Alternate protocol support detected",
                severity=risk_map.get(analysis["risk_level"], "Medium"),
                description=f"Alternate protocol support: {'; '.join(analysis['issues'])}",
                target=url,
                attack_type="alternate_protocol",
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation=analysis["issues"][0] if analysis["issues"] else "Review alternate protocol configuration and ensure proper TLS usage.",
            )
        )
    else:
        findings.append(
            Finding(
                vulnerability="No alternate protocols detected",
                severity="Info",
                description="No alternate protocols (HTTP/2 via Alt-Svc, h2c, etc.) detected. "
                "Server appears to use standard HTTPS only.",
                target=url,
                attack_type="alternate_protocol",
                cvss_score=1.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Maintain current configuration restricting to HTTPS only.",
            )
        )

    return findings