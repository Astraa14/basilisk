"""CRLF injection and HTTP response splitting detection.

Implements: HTTP Request Smuggling via CRLF injection, Request Splitting,
and HTTP Response Splitting (RPoisoning) detection.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

CRLF = "\r\n"
CRLF_DOUBLE = "\r\n\r\n"

# CRLF injection points
INJECTION_POINTS: List[str] = ["header", "body", "parameter"]

# Detection indicators for response splitting
SPLITTING_INDICATORS: List[str] = [CRLF_DOUBLE, "HTTP/", "\n", "\r"]

# Common header names used in smuggling
SMUGGLING_HEADERS: List[str] = [
    "Transfer-Encoding",
    "Content-Length",
    "Content-Type",
    "Host",
    "Location",
]


def inject_crlf(
    data: str,
    position: str = "header",
    header_name: str = "X-Test",
) -> str:
    """Inject CRLF into HTTP data at the specified position.

    Args:
        data: The HTTP request/response data.
        position: Where to inject - "header", "body", or "parameter".
        header_name: Header name to use for injection (if position="header").

    Returns:
        Data with CRLF injected.
    """
    if position == "header":
        if header_name in data:
            idx = data.index(header_name)
            return data[:idx] + header_name + CRLF + "X-Injected: test" + CRLF + data[idx + len(header_name):]
    elif position == "body":
        if CRLF in data:
            last_crlf = data.rfind(CRLF)
            return data[:last_crlf + 1] + CRLF + "X-Injected: test" + data[last_crlf + 1:]
    elif position == "parameter":
        return data.replace("X-Inject", CRLF + "X-Injected")
    return data


def detect_request_splitting(
    original_resp: dict,
    smuggled_resp: dict,
) -> Tuple[bool, List[str]]:
    """Detect if request splitting was successful.

    Args:
        original_resp: Response from original request.
        smuggled_resp: Response from smuggled/request-split request.

    Returns:
        (is_splitting, evidence) evidence list.
    """
    evidence: List[str] = []
    is_splitting = False

    orig_body = original_resp.get("body", "")
    smuggled_body = smuggled_resp.get("body", "")

    orig_status = original_resp.get("status_code")
    smuggled_status = smuggled_resp.get("status_code")

    if orig_status != smuggled_status:
        is_splitting = True
        evidence.append(
            f"Status code changed from {orig_status} to {smuggled_status} "
            f"(request splitting possible)"
        )

    # Check for CRLF indicators in the smuggled response body
    for indicator in SPLITTING_INDICATORS:
        if indicator in smuggled_body:
            is_splitting = True
            evidence.append(f"Splitting indicator found in body: {indicator}")

    # Check for HTTP response line in body (response splitting)
    if re.search(r"HTTP/\d\.\d\s+\d{3}", smuggled_body):
        is_splitting = True
        evidence.append("HTTP response line found in response body (splitting)")

    return is_splitting, evidence


def detect_response_splitting(
    original_resp: dict,
    split_resp: dict,
) -> Tuple[bool, List[str]]:
    """Detect if response splitting was successful.

    Args:
        original_resp: Response from original request.
        split_resp: Response from request that may have caused splitting.

    Returns:
        (is_splitting, evidence) evidence list.
    """
    evidence: List[str] = []
    is_splitting = False

    orig_body = original_resp.get("body", "")
    split_body = split_resp.get("body", "")

    # Check for CRLF doubling in the split response
    if CRLF_DOUBLE in split_body:
        is_splitting = True
        evidence.append("CRLF doubling detected in response body")

    # Check for HTTP status line in body
    if re.search(r"HTTP/\d\.\d\s+\d{3}", split_body):
        is_splitting = True
        evidence.append("HTTP status line found in response body")

    # Check for double CRLF patterns that would split responses
    if split_body.count(CRLF) > orig_body.count(CRLF) * 1.5:
        is_splitting = True
        evidence.append(
            f"Response has disproportionate number of CRLF sequences "
            f"(orig: {orig_body.count(chr(10) + chr(13))}, split: {split_body.count(chr(10) + chr(13))})"
        )

    return is_splitting, evidence


def crlf_injection_fuzzer(
    engine,
    url: str,
    injection_points: List[str] | None = None,
    timeout: float = 5.0,
) -> List[Finding]:
    """Fuzz a URL with CRLF injection for request smuggling/splitting.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        injection_points: Points to inject CRLF (header, body, parameter).
        timeout: Request timeout.

    Returns:
        List of Findings from CRLF injection fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: List[Finding] = []

    if injection_points is None:
        injection_points = INJECTION_POINTS

    # First, send original request
    orig_response = engine.send("GET", url, timeout=timeout)
    if not orig_response:
        return findings

    for point in injection_points:
        # Inject CRLF at the specified point
        injected_data = inject_crlf(url, position=point)
        smuggled_response = engine.send("GET", injected_data, timeout=timeout)
        if not smuggled_response:
            continue

        # Detect both types of splitting
        is_splitting, evidence = detect_request_splitting(orig_response, smuggled_response)
        if is_splitting:
            cvss, vector = 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            findings.append(
                Finding(
                    vulnerability="HTTP request splitting via CRLF injection",
                    severity="High",
                    description=f"Request splitting possible via CRLF injection at {point}: "
                    f"{'|'.join(evidence[:3])}",
                    target=url,
                    attack_type="req_split",
                    cvss_score=cvss,
                    cvss_vector=vector,
                )
            )

        is_splitting2, evidence2 = detect_response_splitting(orig_response, smuggled_response)
        if is_splitting2:
            cvss, vector = 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            findings.append(
                Finding(
                    vulnerability="HTTP response splitting via CRLF injection",
                    severity="High",
                    description=f"Response splitting possible via CRLF injection at {point}: "
                    f"{'|'.join(evidence2[:3])}",
                    target=url,
                    attack_type="resp_split",
                    cvss_score=cvss,
                    cvss_vector=vector,
                )
            )

    return findings


def header_based_smuggling(
    engine,
    url: str,
    headers_to_inject: List[str] | None = None,
    timeout: float = 5.0,
) -> List[Finding]:
    """Fuzz a URL with header-based HTTP smuggling payloads.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        headers_to_inject: Header names to inject CRLF into.
        timeout: Request timeout.

    Returns:
        List of Findings from header-based smuggling fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: List[Finding] = []

    if headers_to_inject is None:
        headers_to_inject = SMUGGLING_HEADERS

    # First, send original request
    orig_response = engine.send("GET", url, timeout=timeout)
    if not orig_response:
        return findings

    for header_name in headers_to_inject:
        # Inject CRLF into the header
        inject_headers = {header_name: CRLF + "X-Test: injected"}
        inject_response = engine.send("GET", url, headers=inject_headers, timeout=timeout)
        if not inject_response:
            continue

        is_splitting, evidence = detect_request_splitting(orig_response, inject_response)
        if is_splitting:
            cvss, vector = 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            findings.append(
                Finding(
                    vulnerability=f"HTTP request smuggling via {header_name} header injection",
                    severity="High",
                    description=f"Request smuggling possible via CRLF injection in {header_name}: "
                    f"{'|'.join(evidence[:3])}",
                    target=url,
                    attack_type="http_smuggling",
                    cvss_score=cvss,
                    cvss_vector=vector,
                )
            )

    return findings