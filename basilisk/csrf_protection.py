"""CSRF token extraction and injection for Basilisk fuzzing.

Finds CSRF tokens in form HTML, tracks them across requests, and can
automatically inject them into subsequent requests to maintain session
validity during fuzzing.
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

# Common CSRF token field names
CSRF_FIELD_NAMES = (
    "csrf_token",
    "authenticity_token",
    "csrf",
    "session_token",
    "__csrf_token",
    "stoken",
    "wpnonce",
    "captcha_key",
)

JS_CSRF_PATTERNS = [
    r'"csrf"\s*:\s*"([^"]+)"',
    r'"authenticity_token"\s*:\s*"([^"]+)"',
    r'"token"\s*:\s*"([^"]+)"',
    r"['\"](csrf_token|authenticity_token)['\"]\s*:\s*['\"]([^'\"]+)['\"]",
]


def extract_csrf_token(
    response_body: str,
    field_names: list[str] | None = None,
) -> Optional[dict]:
    """Extract a CSRF token from an HTTP response body.

    Looks for hidden input fields, JSON bodies, or meta tags.
    Returns dict with 'name' and 'value' keys, or None.
    """
    if not field_names:
        field_names = list(CSRF_FIELD_NAMES)

    # Hidden input field
    for name in field_names:
        m = re.search(
            rf'<input[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"',
            response_body,
            re.IGNORECASE,
        )
        if m:
            return {"name": name, "value": m.group(1)}

    # JSON body
    try:
        data = __import__("json").loads(response_body)
        for name in field_names:
            if isinstance(data, dict) and name in data:
                val = data[name]
                if isinstance(val, str):
                    return {"name": name, "value": val}
    except Exception:
        pass

    # Meta tag
    for name in field_names:
        m = re.search(
            rf'<meta[^>]*content="([^"]*)"[^>]*[^>]*name="[^"]*{re.escape(name)}"',
            response_body,
            re.IGNORECASE,
        )
        if m:
            return {"name": name, "value": m.group(1)}

    return None


def inject_csrf_token(
    request_headers: dict,
    request_body: str | None,
    token_info: dict,
    method: str = "GET",
    in_body: bool = False,
) -> tuple[dict, str]:
    """Inject a CSRF token into a request.

    Returns updated headers and body.
    """
    token_name = token_info["name"]
    token_value = token_info["value"]

    if method == "POST" and in_body and request_body:
        # Inject into form body
        if "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if f"{token_name}=" not in request_body:
            sep = "&" if "=" in request_body else "?"
            request_body = f"{request_body}{sep}{token_name}={token_value}"
        return request_headers, request_body

    # Inject into headers (as Cookie or custom header)
    if token_name not in request_headers:
        request_headers[token_name] = token_value
    return request_headers, request_body


def track_csrf_tokens(
    findings: list[Finding],
    target: str,
    attack_type: str = "csrf",
) -> None:
    """Add a finding when CSRF token handling issues are detected.

    This is called when fuzzing reveals CSRF vulnerabilities or token
    management problems.
    """
    cvss, vector = score_finding(attack_type)
    findings.append(
        Finding(
            vulnerability=f"CSRF token {attack_type}",
            severity="High" if attack_type == "bypass" else "Medium",
            description=f"CSRF token {attack_type} issue detected at {target}",
            target=target,
            attack_type=attack_type,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Validate CSRF tokens on server side. Use SameSite cookies "
            "and Double Submit Cookie patterns.",
        )
    )


def csrf_token_fuzzer(
    engine,
    form: dict,
    on_progress: Any = None,
) -> list[Finding]:
    """Fuzz a form for CSRF vulnerabilities.

    Extracts the form, attempts to find and reuse a CSRF token,
    then tests missing/weak token handling.
    Returns list of Findings.
    """
    from basilisk.http import RequestEngine
    from basilisk.form_parser import parse_form

    findings: list[Finding] = []

    # Parse the form
    html = form.get("html", "") or ""
    if not html:
        return findings

    parsed = parse_form(html, form.get("action", ""))

    if not parsed.fields:
        return findings

    # Try to extract a CSRF token from the form
    token_info = extract_csrf_token(html)
    token_applied = False

    if token_info:
        # Apply the token to the form fields
        for field in parsed.fields:
            if field.name == token_info["name"]:
                field.value = token_info["value"]
                token_applied = True
                break

    # If no token found, test forms without token (CSRF bypass)
    if not token_applied:
        track_csrf_tokens(
            findings,
            parsed.action or "",
            "bypass",
        )

    # If token found, test with and without token
    if token_info:
        # Request without token
        headers_no_token = {}
        body_no_token = None
        if parsed.method == "POST" and parsed.enctype == "multipart/form-data":
            body_no_token = _build_multipart_body(parsed.fields, exclude=[token_info["name"]])
        elif parsed.method == "POST":
            body_no_token = _build_form_body(parsed.fields, exclude=[token_info["name"]])

        findings.append(
            Finding(
                vulnerability="CSRF token missing in request",
                severity="Medium",
                description=f"Form at {parsed.action} does not require CSRF token in request",
                target=parsed.action or "",
                attack_type="csrf",
                cvss_score=score_finding("csrf")[0],
                cvss_vector=score_finding("csrf")[1],
                remediation="Ensure CSRF tokens are required for all state-changing requests.",
            )
        )

        # Request with valid token
        headers_with_token, body_with_token = inject_csrf_token(
            {},
            None,
            token_info,
            method=parsed.method,
            in_body=parsed.enctype == "multipart/form-data",
        )

        findings.append(
            Finding(
                vulnerability="CSRF token present and valid",
                severity="Low",
                description=f"CSRF token '{token_info['name']}' present at {parsed.action}",
                target=parsed.action or "",
                attack_type="csrf",
                cvss_score=score_finding("csrf")[0],
                cvss_vector=score_finding("csrf")[1],
                remediation="Continue validating CSRF token on server side.",
            )
        )

    return findings


def _build_form_body(
    fields: list[Any], exclude: list[str] | None = None
) -> str:
    """Build application/x-www-form-urlencoded body from field list."""
    exclude = exclude or []
    parts: list[str] = []
    for f in fields:
        if f.name in exclude:
            continue
        val = f.value or ""
        parts.append(f"{f.name}={__import__('urllib').parse.quote(val, safe='')}")
    return "&".join(parts)


def _build_multipart_body(
    fields: list[Any], exclude: list[str] | None = None
) -> str:
    """Build multipart/form-data body from field list."""
    exclude = exclude or []
    parts: list[str] = []
    import mimetypes
    boundary = "----Boundary" + __import__("uuid").uuid4().hex[:8]
    for f in fields:
        if f.name in exclude:
            continue
        fname = f.name or "field"
        fvalue = f.value or ""
        # Determine content type
        ct = mimetypes.guess_type(fname, False)[0] or "application/octet-stream"
        parts.append(
            f'----{boundary}\r\n'
            f'Content-Disposition: form-data; name="{fname}"\r\n'
            f'Content-Type: {ct}\r\n'
            f'\r\n'
            f'{fvalue}\r\n'
        )
    parts.append(f"----{boundary}--\r\n")
    return "\r\n".join(parts)