"""Header injection and Host header injection detection for cache poisoning.

Provides: arbitrary header injection fuzzing, Host header manipulation
for cache poisoning, and detection of vulnerable servers.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# CRLF characters for header injection
CRLF = "\r\n"

# Common header names vulnerable to injection
VULNERABLE_HEADERS: list[str] = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-URL",
    "Host",
    "Location",
    "Referer",
    "Origin",
]

# Injection payloads for CRLF / header injection
HEADER_INJECTION_PAYLOADS: list[str] = [
    CRLF + "X-Inject: test",
    CRLF + "\r\nX-Inject: test",
    CRLF + "\nX-Inject: test",
]


def inject_header(
    base_headers: dict,
    header_name: str,
    header_value: str,
    crlf: str = CRLF,
) -> dict:
    """Inject a header into a headers dict using CRLF injection.

    Useful for testing header injection / response splitting vulnerabilities.
    Returns the modified headers dict.
    """
    headers = dict(base_headers)
    # Prepend CRLF to inject into subsequent headers
    injected = f"{header_name}: {header_value}{crlf}"
    # Find existing headers and inject before them, or append
    # Simple approach: append with CRLF injection
    headers[header_name] = header_value
    # Also inject a second header that captures the CRLF
    headers["X-Inject"] = "injected"
    return headers


def host_header_injection(
    original_host: str,
    injection_payload: str,
) -> str:
    """Construct a Host header with injection payload for cache poisoning.

    Args:
        original_host: The legitimate hostname.
        injection_payload: CRLF-injected payload.

    Returns:
        Full Host header value with injection.
    """
    return f"{original_host}{CRLF}{injection_payload}"


def detect_header_injection(
    original_resp: dict,
    injected_resp: dict,
) -> tuple[bool, list[str]]:
    """Detect if header injection was successful by comparing responses.

    Args:
        original_resp: Response dict from original request.
        injected_resp: Response dict from request with injected headers.

    Returns:
        (is_injected, evidence) evidence list.
    """
    evidence: list[str] = []
    is_injected = False

    # Check if new headers appeared in the injected response
    orig_headers = original_resp.get("headers", {})
    injected_headers = injected_resp.get("headers", {})

    # Look for our injected header
    for key in injected_headers:
        if key not in orig_headers or injected_headers[key] != orig_headers.get(key):
            is_injected = True
            evidence.append(f"Header '{key}' was injected or modified")

    # Look for CRLF-based response splitting indicators
    body = injected_resp.get("body", "")
    if "\r\n\r\n" in body and body.count("\r\n") > body.split("\r\n\r\n")[0].count("\r\n"):
        is_injected = True
        evidence.append("Response body contains unusual CRLF patterns (possible response splitting)")

    return is_injected, evidence


def header_injection_fuzzer(
    engine,
    url: str,
    headers_to_inject: list[str] | None = None,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL with header injection payloads.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        headers_to_inject: List of header names to inject.
        timeout: Request timeout.

    Returns:
        List of Findings from header injection fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    if headers_to_inject is None:
        headers_to_inject = VULNERABLE_HEADERS

    # First, send original request
    orig_response = engine.send("GET", url, timeout=timeout)
    if not orig_response:
        return findings

    for header_name in headers_to_inject:
        # Inject the header
        injected_headers = {header_name: CRLF + "X-Test:injected"}
        injected_response = engine.send("GET", url, headers=injected_headers, timeout=timeout)
        if not injected_response:
            continue

        is_injected, evidence = detect_header_injection(orig_response, injected_response)

        if is_injected:
            cvss, vector = score_finding("header_inj")
            findings.append(
                Finding(
                    vulnerability=f"Header injection via {header_name}",
                    severity="High" if "Host" in header_name else "Medium",
                    description=f"Header injection possible through {header_name}: "
                    f"{'|'.join(evidence[:3])}",
                    target=url,
                    attack_type="header_inj",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation=f"Sanitize and validate the {header_name} header server-side. "
                    "Do not trust client-supplied header values.",
                )
            )
        else:
            # Still log as info
            findings.append(
                Finding(
                    vulnerability=f"No header injection detected via {header_name}",
                    severity="Low",
                    description=f"Header injection not detected via {header_name}",
                    target=url,
                    attack_type="header_inj",
                    cvss_score=score_finding("header_inj")[0],
                    cvss_vector=score_finding("header_inj")[1],
                    remediation="Ensure server properly validates all header values.",
                )
            )

    return findings


def host_header_poisoning_fuzzer(
    engine,
    host: str,
    original_path: str = "/",
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz the Host header for cache poisoning / Host header injection.

    Args:
        engine: RequestEngine instance.
        host: Target hostname.
        original_path: Original path to use.
        timeout: Request timeout.

    Returns:
        List of Findings from Host header injection fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Test with just the host
    orig_headers = {"Host": host}
    orig_response = engine.send("GET", f"http://{host}{original_path}", headers=orig_headers, timeout=timeout)
    if not orig_response:
        return findings

    # Test with CRLF injection in Host header
    crlf_payload = CRLF + "X-Forwarded-For: attacker.com"
    inject_headers = {"Host": host + crlf_payload}
    inject_response = engine.send("GET", f"http://{host}{original_path}", headers=inject_headers, timeout=timeout)
    if not inject_response:
        return findings

    is_injected, evidence = detect_header_injection(orig_response, inject_response)

    if is_injected:
        cvss, vector = score_finding("host_inj")
        findings.append(
            Finding(
                vulnerability="Host header injection for cache poisoning",
                severity="High",
                description=f"Host header injection possible for cache poisoning: "
                f"{'|'.join(evidence[:3])}",
                target=f"http://{host}{original_path}",
                attack_type="host_inj",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate and sanitize the Host header. Use canonical Host header "
                "processing and avoid forwarding based on unsanitized Host values.",
            )
        )

    # Test with double CRLF for response splitting
    inject_headers2 = {"Host": host + CRLF + CRLF + "X-Inject: test"}
    inject_response2 = engine.send("GET", f"http://{host}{original_path}", headers=inject_headers2, timeout=timeout)
    if not inject_response2:
        return findings

    is_injected2, evidence2 = detect_header_injection(orig_response, inject_response2)

    if is_injected2:
        cvss, vector = score_finding("host_inj")
        findings.append(
            Finding(
                vulnerability="Host header injection with response splitting",
                severity="High",
                description=f"Host header injection enables response splitting: "
                f"{'|'.join(evidence2[:3])}",
                target=f"http://{host}{original_path}",
                attack_type="host_inj",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Same as above - validate Host header server-side.",
            )
        )

    return findings