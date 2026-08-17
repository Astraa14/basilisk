"""Range request abuse detection.

Detects servers that are vulnerable to range request manipulation, which can
lead to cache poisoning, content bypass, or information disclosure.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Common range request patterns
RANGE_PATTERNS: list[str] = [
    "Range: bytes=",
    "If-Range:",
]

# Range response status codes
RANGE_STATUSES: list[int] = [206, 416, 200]

# Range abuse indicators
RANGE_ABUSE_INDICATORS: list[dict] = [
    {
        "name": "range_poisoning",
        "description": "Server accepts overlapping ranges that can cause "
        "cache poisoning or content bypass",
        "pattern": r"Range: bytes=\\d+-\\d+,\\d+-\\d+",
    },
    {
        "name": "range_overflow",
        "description": "Server accepts ranges beyond file size, "
        "potentially returning entire file",
        "pattern": r"Range: bytes=\\d+-",
    },
    {
        "name": "range_ignore_content_type",
        "description": "Server accepts range requests regardless of "
        "Content-Type, potentially bypassing filters",
        "pattern": r"Range.*\\n.*Content-Range",
    },
]


def analyze_range_request(
    original_resp: dict,
    range_resp: dict,
) -> tuple[bool, list[str]]:
    """Analyze range request response for abuse indicators.

    Args:
        original_resp: Original (non-range) response.
        range_resp: Response to a Range request.

    Returns:
        (is_abuse, evidence) evidence list.
    """
    evidence: list[str] = []
    is_abuse = False

    orig_status = original_resp.get("status_code")
    range_status = range_resp.get("status_code")

    orig_body = original_resp.get("body", "")[:200]
    range_body = range_resp.get("body", "")[:200]

    # Check status code differences
    if range_status != orig_status:
        is_abuse = True
        evidence.append(
            f"Range request returned different status ({range_status} vs {orig_status})"
        )

    # Check for range poisoning (overlapping ranges)
    range_header = range_resp.get("headers", {}).get("Range", "")
    if re.search(r"bytes=\\d+-\\d+,\\d+-\\d+", range_header):
        is_abuse = True
        evidence.append("Range poisoning: overlapping ranges detected")

    # Check for range overflow (beyond file size)
    if re.search(r"Range: bytes=\\d+-.", range_header):
        is_abuse = True
        evidence.append("Range overflow: range beyond file size")

    # Check for content type bypass
    if re.search(r"Range.*\\n.*Content-Range", range_resp.get("headers", {}).get("Content-Range", "")):
        is_abuse = True
        evidence.append("Range request bypassed content-type filtering")

    # Check for body content differences that indicate bypass
    if range_body != orig_body[: len(range_body)] and range_status == 200:
        is_abuse = True
        evidence.append("Range request returned full content despite range header")

    return is_abuse, evidence


def range_abuse_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL with Range request abuse detection.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        timeout: Request timeout.

    Returns:
        List of Findings from range request abuse fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # First, send original request without Range header
    orig_response = engine.send("GET", url, timeout=timeout)
    if not orig_response:
        return findings

    # Parse Content-Length or Content-Range from original response
    orig_body_size = len(orig_response.get("body", "") or "")

    # Test with Range request for a portion of the content
    range_header = f"Range: bytes=0-{orig_body_size // 10}"  # First 10%
    range_response = engine.send(
        "GET", url, headers={"Range": range_header}, timeout=timeout
    )
    if not range_response:
        return findings

    is_abuse, evidence = analyze_range_request(orig_response, range_response)

    if is_abuse:
        cvss, vector = 6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        findings.append(
            Finding(
                vulnerability="Range request abuse detected",
                severity="Medium",
                description=f"Range request abuse possible: {'; '.join(evidence[:3])}",
                target=url,
                attack_type="range_abuse",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate range requests server-side. Ensure ranges are "
                "properly bounded and overlapping ranges are rejected.",
            )
        )
    else:
        # Also test with a range beyond the file size
        range_header2 = f"Range: bytes={orig_body_size}-{orig_body_size * 10}"
        range_response2 = engine.send(
            "GET", url, headers={"Range": range_header2}, timeout=timeout
        )
        if range_response2:
            # If server returns 200 for beyond-range, that's abuse
            if range_response2.get("status_code") == 200:
                cvss, vector = 7.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                findings.append(
                    Finding(
                        vulnerability="Range request beyond file size returned 200",
                        severity="Medium",
                        description="Server returned full content for range request "
                        "beyond file size, indicating range abuse possible",
                        target=url,
                        attack_type="range_abuse",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Validate range requests against file size. "
                        "Return 416 Range Not Satisfiable for out-of-range requests.",
                    )
                )
            elif range_response2.get("status_code") == 416:
                # Proper behavior - 416 means range not satisfiable
                pass

    return findings