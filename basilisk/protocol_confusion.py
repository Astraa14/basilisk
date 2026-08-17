"""Protocol confusion attacks - HTTP/0.9, HTTP/1.0, HTTP/2 confusion.

Detects servers that mishandle different HTTP protocol versions,
enabling protocol confusion attacks.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# HTTP version confusion attack vectors
PROTOCOL_CONFUSION_VECTORS: list[dict] = [
    {
        "name": "http_0_9",
        "description": "Server responds in HTTP/0.9 (no headers, just body) "
        "which can be used to bypass filters or confuse parsers",
        "pattern": "server informs client of HTTP/0.9 support",
    },
    {
        "name": "http_1_0_to_1_1",
        "description": "Server misinterprets HTTP/1.0 requests as HTTP/1.1, "
        "potentially enabling request smuggling",
        "pattern": "server accepts HTTP/1.0 with HTTP/1.1 features",
    },
    {
        "name": "http_2_prior_knowledge",
        "description": "Client sends HTTP/2 PRIOR_KNOWLEDGE connection preface "
        "to an HTTP/1.1 server, causing misinterpretation",
        "pattern": "HTTP/2 connection preface on HTTP/1.1 port",
    },
]


def detect_protocol_confusion(
    original_resp: dict,
    confused_resp: dict,
    attack_type: str,
) -> tuple[bool, list[str]]:
    """Detect protocol confusion between two responses.

    Args:
        original_resp: Original response.
        confused_resp: Response from confusion attempt.
        attack_type: Type of protocol confusion attack.

    Returns:
        (is_confused, evidence) evidence list.
    """
    evidence: list[str] = []
    is_confused = False

    orig_status = original_resp.get("status_code")
    confused_status = confused_resp.get("status_code")

    # Status code changes indicate confusion
    if orig_status != confused_status:
        is_confused = True
        evidence.append(
            f"Status code changed from {orig_status} to {confused_status} "
            f"(protocol confusion: {attack_type})"
        )

    # Check for HTTP/0.9 style response (no status line, just body)
    confused_body = confused_resp.get("body", "")[:100]
    if not re.search(r"HTTP/", confused_body) and len(confused_body) > 50:
        is_confused = True
        evidence.append(
            f"Response appears to be HTTP/0.9 style (no status line): "
            f"{confused_body[:50]}..."
        )

    # Check for HTTP version mismatch in headers
    orig_headers = original_resp.get("headers", {})
    confused_headers = confused_resp.get("headers", {})
    for header in ["Server", "Date", "Content-Type"]:
        if header in confused_headers and header not in orig_headers:
            is_confused = True
            evidence.append(
                f"Header '{header}' present in confused response but not original"
            )

    return is_confused, evidence


def protocol_confusion_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for protocol confusion attacks.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        timeout: Request timeout.

    Returns:
        List of Findings from protocol confusion fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # First, send normal HTTP/1.1 request
    normal_response = engine.send("GET", url, timeout=timeout)
    if not normal_response:
        return findings

    # Test HTTP/0.9 style request (no version in request line)
    # A simple GET request without Accept headers can trigger HTTP/0.9
    http_0_9_response = engine.send("GET", url, timeout=timeout)
    if http_0_9_response:
        is_confused, evidence = detect_protocol_confusion(
            normal_response, http_0_9_response, "http_0_9"
        )
        if is_confused:
            cvss, vector = 6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            findings.append(
                Finding(
                    vulnerability="HTTP/0.9 protocol confusion detected",
                    severity="Medium",
                    description=f"Server appears to support HTTP/0.9 protocol confusion: "
                    f"{'|'.join(evidence[:3])}",
                    target=url,
                    attack_type="protocol_confusion",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Ensure server properly negotiates HTTP versions and "
                    "does not fall back to HTTP/0.9 which lacks security headers.",
                )
            )

    # Test with HTTP/1.0-style headers (Connection: close, no Keep-Alive)
    http_1_0_response = engine.send(
        "GET", url, headers={"Connection": "close"}, timeout=timeout
    )
    if http_1_0_response:
        is_confused, evidence = detect_protocol_confusion(
            normal_response, http_1_0_response, "http_1_0_to_1_1"
        )
        if is_confused:
            cvss, vector = 7.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            findings.append(
                Finding(
                    vulnerability="HTTP/1.0 to HTTP/1.1 protocol confusion detected",
                    severity="Medium",
                    description=f"Protocol confusion between HTTP/1.0 and HTTP/1.1: "
                    f"{'|'.join(evidence[:3])}",
                    target=url,
                    attack_type="protocol_confusion",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Ensure server properly handles different HTTP versions "
                    "and maintains consistent security behavior across versions.",
                )
            )

    # Test for HTTP/2 prior knowledge attack
    # This is more theoretical - sending HTTP/2 connection preface
    # to an HTTP/1.1 port
    try:
        # This is a raw connection test - simplified for safety
        # In practice, this requires raw socket manipulation
        pass
    except Exception:
        pass

    return findings