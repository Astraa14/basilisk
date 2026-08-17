"""Content-Encoding bypass techniques.

Detects servers that mishandle Content-Encoding headers, which can be exploited
to bypass security controls, access compressed source code, or facilitate
request smuggling.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Content-Encoding bypass techniques
ENCODING_BYPASS_TECHNIQUES: list[dict] = [
    {
        "name": "double_encoding",
        "description": "Server applies double Content-Encoding (e.g., gzip then "
        "chunked) which can cause parser confusion",
        "pattern": r"Content-Encoding:.*gzip.*Content-Encoding:",
    },
    {
        "name": "chunked_with_encoding",
        "description": "Chunked transfer encoding with Content-Encoding can "
        "cause some parsers to miss the encoding",
        "pattern": r"Transfer-Encoding: chunked.*Content-Encoding:",
    },
    {
        "name": "identity_misleading",
        "description": "Server claims identity encoding but body is compressed, "
        "causing downstream systems to misinterpret content",
        "pattern": r"Content-Encoding: identity",
    },
]

# Safe encoding patterns
SAFE_ENCODING_PATTERNS: list[dict] = [
    {
        "name": "single_gzip",
        "description": "Single gzip encoding is standard and safe",
        "pattern": r"Content-Encoding: gzip",
    },
    {
        "name": "single_deflate",
        "description": "Single deflate encoding is standard and safe",
        "pattern": r"Content-Encoding: deflate",
    },
]


def analyze_encoding(
    headers: dict,
    body: str,
) -> dict:
    """Analyze Content-Encoding headers for bypass risks.

    Args:
        headers: Response headers.
        body: Response body content.

    Returns:
        dict with encoding analysis results.
    """
    result: dict = {
        "encoding": None,
        "bypasses": [],
        "risk_level": "low",
        "issues": [],
    }

    # Get Content-Encoding
    encoding = headers.get("Content-Encoding", "")
    result["encoding"] = encoding.lower() if encoding else None

    # Check for double encoding
    if re.search(
        r"Content-Encoding.*Content-Encoding",
        headers.get("Content-Encoding", ""),
        re.IGNORECASE,
    ):
        result["bypasses"].append("Double Content-Encoding detected")
        result["risk_level"] = "high"
        result["issues"].append("Double encoding can cause parser confusion")

    # Check for chunked + encoding combination
    te = headers.get("Transfer-Encoding", "")
    if encoding and "chunked" in te.lower():
        result["bypasses"].append(
            "Chunked transfer encoding with Content-Encoding"
        )
        if result["risk_level"] != "high":
            result["risk_level"] = "medium"
        result["issues"].append(
            "Transfer-Encoding and Content-Encoding combination"
        )

    # Check for misleading identity encoding
    if encoding == "identity" and len(body) > 0:
        # Check if body appears compressed
        if body[:2] in (b"\x1f\x8b", b"\x04\x22", b"PK") or (
            body.startswith("<!") and b"gzip" in body[:100].lower()
        ):
            result["bypasses"].append(
                "Identity encoding with compressed body detected"
            )
            result["risk_level"] = "high"
            result["issues"].append(
                "Server claims identity but body appears compressed"
            )

    # Check for safe encoding
    for safe in SAFE_ENCODING_PATTERNS:
        if re.search(safe["pattern"], headers.get("Content-Encoding", ""), re.IGNORECASE):
            result["bypasses"].append(safe["description"])
            if result["risk_level"] == "low":
                result["risk_level"] = "info"

    return result


def encoding_bypass_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for Content-Encoding bypass detection.

    Args:
        engine: RequestEngine instance.
        url: Target URL to analyze.
        timeout: Request timeout.

    Returns:
        List of Findings from Content-Encoding bypass fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Send request and get headers
    response = engine.send("GET", url, timeout=timeout)
    if not response:
        return findings

    headers = response.get("headers", {})
    body = response.get("body", "")

    analysis = analyze_encoding(headers, body)

    if analysis["bypasses"]:
        risk_map = {"high": "High", "medium": "Medium", "info": "Info"}
        cvss_map = {
            "high": 7.5,
            "medium": 6.5,
            "info": 2.0,
        }
        cvss = cvss_map.get(analysis["risk_level"], 5.3)

        findings.append(
            Finding(
                vulnerability="Content-Encoding bypass technique detected",
                severity=risk_map.get(analysis["risk_level"], "Medium"),
                description=f"Content-Encoding bypass: {'; '.join(analysis['bypasses'])}",
                target=url,
                attack_type="content_encoding_bypass",
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation=analysis["issues"][0]
                if analysis["issues"]
                else "Review Content-Encoding and Transfer-Encoding header handling.",
            )
        )
    else:
        findings.append(
            Finding(
                vulnerability="Content-Encoding properly handled",
                severity="Info",
                description="Content-Encoding appears properly configured with no bypass vectors detected.",
                target=url,
                attack_type="content_encoding_bypass",
                cvss_score=1.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Maintain current encoding configuration.",
            )
        )

    return findings