"""HTTP TRACK method detection.

Detects if the TRACK method is enabled on a server, which can be exploited
for HTTP request smuggling and other attacks.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# TRACK method is an extension of HTTP that allows tunneling of other protocols
TRACK_METHOD = "TRACK"

# Safe list of allowed methods
SAFE_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# TRACK is often disabled by default, but some servers enable it incorrectly
TRACK_PAYLOAD: str = TRACK_METHOD + " / HTTP/1.1\r\nHost: target\r\n\r\n"


def check_track_method(
    engine,
    url: str,
    timeout: float = 5.0,
) -> tuple[bool, Optional[dict]]:
    """Check if the TRACK method is enabled on the server.

    Args:
        engine: RequestEngine instance.
        url: Target URL to check.
        timeout: Request timeout.

    Returns:
        (is_enabled, response_info) tuple.
    """
    from basilisk.http import RequestEngine

    # Send TRACK method request
    track_response = engine.send(TRACK_METHOD, url, timeout=timeout)
    if not track_response:
        return False, None

    is_enabled = track_response.get("status_code") in (200, 301, 302, 303, 307, 308)

    response_info = {
        "status_code": track_response.get("status_code"),
        "headers": dict(track_response.get("headers", {})),
        "body": track_response.get("body", "")[:200],
    }

    return is_enabled, response_info


def track_method_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for TRACK method enabled state.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        timeout: Request timeout.

    Returns:
        List of Findings from TRACK method fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    is_enabled, response_info = check_track_method(engine, url, timeout)

    if is_enabled:
        cvss, vector = 7.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        findings.append(
            Finding(
                vulnerability="TRACK method enabled",
                severity="Medium",
                description="TRACK method is enabled on the server, "
                "which can be exploited for HTTP request smuggling and "
                "tunneling other protocols",
                target=url,
                attack_type="track_method",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Disable the TRACK method on the server. "
                "Most web servers disable this method by default.",
            )
        )
    else:
        # Also check if server responds with 405 (Method Not Allowed)
        # which is the expected secure behavior
        if response_info and response_info.get("status_code") == 405:
            findings.append(
                Finding(
                    vulnerability="TRACK method properly disabled",
                    severity="Info",
                    description="TRACK method is properly disabled (405 Method Not Allowed)",
                    target=url,
                    attack_type="track_method",
                    cvss_score=2.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    remediation="Maintain TRACK method disabled configuration.",
                )
            )
        else:
            findings.append(
                Finding(
                    vulnerability="TRACK method status unknown",
                    severity="Low",
                    description=f"TRACK method status: {response_info.get('status_code') if response_info else 'no response'}",
                    target=url,
                    attack_type="track_method",
                    cvss_score=3.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    remediation="Investigate server TRACK method configuration.",
                )
            )

    return findings