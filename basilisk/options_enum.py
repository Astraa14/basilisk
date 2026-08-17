"""OPTIONS method enumeration for exposed methods.

Detects HTTP methods supported by a server via the OPTIONS response,
identifying potentially dangerous methods that should not be exposed.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Methods that are dangerous if exposed
DANGEROUS_METHODS: list[str] = [
    "TRACE",
    "TRACK",
    "CONNECT",
    "DEBUG",
]

# Safe methods that are typically okay to expose
SAFE_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]

# Methods that indicate WebDAV support
WEBDAV_METHODS: list[str] = ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]


def enumerate_options(
    engine,
    url: str,
    timeout: float = 5.0,
) -> dict:
    """Enumerate HTTP methods supported by the server via OPTIONS.

    Args:
        engine: RequestEngine instance.
        url: Target URL to enumerate.
        timeout: Request timeout.

    Returns:
        dict with enumerated methods and security assessment.
    """
    from basilisk.http import RequestEngine

    result: dict = {
        "methods": [],
        "dangerous_methods": [],
        "webdav_methods": [],
        "safety_assessment": "unknown",
    }

    # Send OPTIONS request
    options_response = engine.send("OPTIONS", url, timeout=timeout)
    if not options_response:
        return result

    # Parse the Allow header
    allow_header = options_response.get("headers", {}).get("Allow", "")
    allow_methods = [m.strip().upper() for m in re.findall(r"\b\w+\b", allow_header)]

    result["methods"] = allow_methods

    # Identify dangerous methods
    for method in allow_methods:
        if method in DANGEROUS_METHODS:
            result["dangerous_methods"].append(method)

    # Identify WebDAV methods
    for method in allow_methods:
        if method in WEBDAV_METHODS:
            result["webdav_methods"].append(method)

    # Safety assessment
    if allow_methods:
        # If dangerous methods are exposed, mark as unsafe
        if result["dangerous_methods"]:
            result["safety_assessment"] = "unsafe"
        # If only safe methods are exposed
        elif not result["dangerous_methods"] and set(allow_methods).issubset(
            set(SAFE_METHODS)
        ):
            result["safety_assessment"] = "safe"
        # If WebDAV methods are exposed
        if result["webdav_methods"]:
            if result["safety_assessment"] == "safe":
                result["safety_assessment"] = "warning_webdav"
            else:
                result["safety_assessment"] = "unsafe_webdav"

    return result


def options_enumeration_fuzzer(
    engine,
    url: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a URL for OPTIONS method enumeration.

    Args:
        engine: RequestEngine instance.
        url: Target URL to fuzz.
        timeout: Request timeout.

    Returns:
        List of Findings from OPTIONS method enumeration fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Enumerate options
    result = enumerate_options(engine, url, timeout)

    # Report dangerous methods
    for method in result.get("dangerous_methods", []):
        cvss, vector = 8.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        findings.append(
            Finding(
                vulnerability=f"Dangerous HTTP method exposed: {method}",
                severity="High",
                description=f"The {method} HTTP method is exposed via OPTIONS response, "
                f"which can be exploited for various attacks including XSS, "
                "CSRF, and request smuggling.",
                target=url,
                attack_type="options_enum",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation=f"Disable the {method} method on the server if not required. "
                "Implement proper method filtering and only expose methods that are "
                "needed for functionality.",
            )
        )

    # Report WebDAV methods
    for method in result.get("webdav_methods", []):
        cvss, vector = 6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        findings.append(
            Finding(
                vulnerability=f"WebDAV method exposed: {method}",
                severity="Medium",
                description=f"The {method} WebDAV method is exposed via OPTIONS response, "
                f"which can be used for file manipulation and remote code execution "
                "in some server configurations.",
                target=url,
                attack_type="webdav_enum",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Restrict WebDAV methods to trusted internal networks only. "
                "Disable WebDAV if not required.",
            )
        )

    # Report safety assessment
    if result.get("safety_assessment") == "unsafe":
        findings.append(
            Finding(
                vulnerability="Multiple dangerous HTTP methods exposed",
                severity="High",
                description=f"Multiple dangerous HTTP methods are exposed via OPTIONS response: "
                f"{', '.join(result.get('dangerous_methods', []))}",
                target=url,
                attack_type="options_enum",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                remediation="Review and disable all unnecessary HTTP methods on the server. "
                "Only expose methods that are absolutely required for functionality.",
            )
        )
    elif result.get("safety_assessment") == "safe":
        findings.append(
            Finding(
                vulnerability="HTTP methods safely restricted",
                severity="Info",
                description="Only safe HTTP methods are exposed via OPTIONS response.",
                target=url,
                attack_type="options_enum",
                cvss_score=1.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                remediation="Maintain current method restrictions.",
            )
        )

    return findings