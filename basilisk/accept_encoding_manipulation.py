"""Accept-Encoding manipulation for response transformation detection.

Detects servers that mishandle Accept-Encoding headers, which can be exploited
to transform responses, bypass content filters, or facilitate caching attacks.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Accept-Encoding manipulation vectors
ACCEPT_ENCODING_VECTORS: list[dict] = [
    {
        "name": "identity_only",
        "description": "Client sends Accept-Encoding: identity only, "
        "forcing uncompressed response for analysis",
        "pattern": r"Accept-Encoding:.*identity",
    },
    {
        "name": "prefer_gzip_deflate",
        "description": "Client prefers gzip/deflate which can be exploited "
        "to reduce bandwidth but may expose compression side-channels",
        "pattern": r"Accept-Encoding:.*gzip.*deflate",
    },
    {
        "name": "browser_spoofing",
        "description": "Spoofed Accept-Encoding to discover server capabilities",
        "pattern": r"Accept-Encoding:.*\\*.*",
    },
]

# Safe Accept-Encoding patterns
SAFE_ACCEPT_ENCODING: list[str] = [
    "gzip, deflate, br",
    "gzip, deflate",
    "identity",
    "*",
]


def analyze_accept_encoding(
    headers: dict,
) -> dict:
    """Analyze Accept-Encoding header for manipulation vectors.

    Args:
        headers: Request headers (Accept-Encoding).

    Returns:
        dict with Accept-Encoding analysis results.
    """
    result: dict = {
        "accept_encoding": None,
        "manipulation_vectors": [],
        "risk_level": "low",
    }

    # Get Accept-Encoding
    ae = headers.get("Accept-Encoding", "")
    result["accept_encoding"] = ae if ae else None

    if not ae:
        result["manipulation_vectors"].append(
            "No Accept-Encoding header - server will decide encoding"
        )
        return result

    ae_lower = ae.lower()

    # Check for identity-only requests
    if re.search(r"identity", ae_lower) and not re.search(
        r"gzip|deflate|br", ae_lower
    ):
        result["manipulation_vectors"].append(
            "Accept-Encoding: identity only may force uncompressed responses"
        )
        result["risk_level"] = "medium"

    # Check for browser feature spoofing (wildcard)
    if re.search(r"\*", ae_lower):
        result["manipulation_vectors"].append(
            "Wildcard Accept-Encoding may reveal server capabilities"
        )
        if result["risk_level"] != "high":
            result["risk_level"] = "medium"

    # Check for preferred encoding order
    if re.search(r"gzip.*deflate", ae_lower):
        result["manipulation_vectors"].append(
            "gzip preferred over deflate may enable compression side-channel attacks"
        )

    # Check for safe patterns
    for safe in SAFE_ACCEPT_ENCODING:
        if ae_lower == safe.lower():
            result["manipulation_vectors"].append(
                f"Safe Accept-Encoding pattern: {safe}"
            )
            break

    return result


def accept_encoding_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for Accept-Encoding manipulation detection.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from Accept-Encoding manipulation fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request with default headers
    response_default = engine.send("GET", url, timeout=timeout)
    if not response_default:
        return findings

    # Send request with Accept-Encoding: identity only
    identity_response = engine.send(
        "GET", url, headers={"Accept-Encoding": "identity"}, timeout=timeout
    )

    # Send request with Accept-Encoding: gzip, deflate
    gzip_response = engine.send(
        "GET", url, headers={"Accept-Encoding": "gzip, deflate"}, timeout=timeout
    )

    if not identity_response or not gzip_response:
        return findings

    identity_headers = identity_response.get("headers", {})
    gzip_headers = gzip_response.get("headers", {})

    # Analyze both responses
    identity_analysis = analyze_accept_encoding(identity_headers)
    gzip_analysis = analyze_accept_encoding(gzip_headers)

    # Check for encoding manipulation
    if identity_analysis["manipulation_vectors"]:
        findings.append(
            Finding(
                vulnerability="Accept-Encoding manipulation detected",
                severity="Medium" if identity_analysis["risk_level"] == "medium" else "Low",
                description=f"Accept-Encoding manipulation: {'; '.join(identity_analysis['manipulation_vectors'])}",
                target=url,
                attack_type="accept_encoding_manipulation",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Review Accept-Encoding header handling and ensure "
                "appropriate encoding based on client capabilities.",
            )
        )

    if gzip_analysis["manipulation_vectors"]:
        findings.append(
            Finding(
                vulnerability="Accept-Encoding manipulation detected (gzip/deflate)",
                severity="Medium",
                description=f"Accept-Encoding manipulation: {'; '.join(gzip_analysis['manipulation_vectors'])}",
                target=url,
                attack_type="accept_encoding_manipulation",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Review Accept-Encoding header handling and ensure "
                "appropriate encoding based on client capabilities.",
            )
        )

    # Check for encoding difference between requests
    identity_enc = identity_headers.get("Content-Encoding", "")
    gzip_enc = gzip_headers.get("Content-Encoding", "")

    if identity_enc != gzip_enc:
        findings.append(
            Finding(
                vulnerability="Content-Encoding varies by Accept-Encoding header",
                severity="Medium",
                description=f"Content-Encoding varies based on Accept-Encoding: "
                f"identity={identity_enc}, gzip/deflate={gzip_enc}",
                target=url,
                attack_type="accept_encoding_manipulation",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Ensure Content-Encoding is consistent regardless of "
                "Accept-Encoding header value. Different encodings based on "
                "client capabilities can lead to caching and filtering issues.",
            )
        )

    return findings