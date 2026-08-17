"""Polyglot file handling for upload vulnerabilities.

Provides: polyglot file generation (files that are valid multiple types),
detection of polyglot acceptance, and magic byte confusion for upload
bypass attacks.
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Polyglot file pairs - files valid as multiple types
POLYGLOT_PAIRS: list[dict] = [
    {
        "name": "php_gif",
        "extensions": [".gif", ".php"],
        "description": "GIF with embedded PHP code (GIF header + PHP at end)",
    },
    {
        "name": "png_exe",
        "extensions": [".exe", ".png"],
        "description": "Executable with PNG header (MZ header + PNG at end)",
    },
    {
        "name": "pdf_js",
        "extensions": [".pdf", ".js"],
        "description": "PDF with embedded JavaScript code",
    },
]

# Magic bytes for common file types
MAGIC_BYTES: dict[str, bytes] = {
    ".gif": b"GIF87a\x01" or b"GIF89a\x01",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".pdf": b"%PDF",
    ".gif_php": b"GIF89a\x01" + b"<?php",
    ".exe_png": b"MZ\x90\x00\x00\x00" + b"\x89PNG\r\n\x1a\n",
}


def generate_polyglot_file(
    base_type: str,
    secondary_type: str,
    extra_data: bytes = b"",
) -> bytes:
    """Generate a polyglot file that is valid as two different types.

    Args:
        base_type: The primary file type.
        secondary_type: The secondary file type to embed.
        extra_data: Additional data to append (e.g., executable code).

    Returns:
        The polyglot file bytes.
    """
    if base_type == ".gif" and secondary_type == ".php":
        # GIF header + PHP closing tag at end
        gif_header = b"GIF89a\x01"
        php_closing = b"<?php\n/* polyglot */\n?>" 
        return gif_header + extra_data + php_closing
    elif base_type == ".exe" and secondary_type == ".png":
        # MZ executable header + PNG at end
        mz_header = b"MZ" + b"\x90" * 8
        png_header = b"\x89PNG\r\n\x1a\n"
        return mz_header + extra_data + png_header
    elif base_type == ".pdf" and secondary_type == ".js":
        # PDF with embedded JS
        pdf_header = b"%PDF-1.4\n%ÿÿÿÿ\x19\x0d\x0d\x0a"
        js_code = b"console.log('polyglot');"
        return pdf_header + extra_data + js_code
    return b""


def detect_polyglot_acceptance(
    engine,
    upload_url: str,
    file_data: bytes,
    filename: str,
    content_type: str,
    timeout: float = 5.0,
) -> tuple[bool, list[str]]:
    """Test if a server accepts a polyglot file upload.

    Args:
        engine: RequestEngine instance.
        upload_url: The upload endpoint URL.
        file_data: The file data to upload.
        filename: The filename to use.
        content_type: The Content-Type header.
        timeout: Request timeout.

    Returns:
        (accepted, evidence) - whether the file was accepted and why.
    """
    from basilisk.http import RequestEngine

    # Upload the polyglot file
    import urllib.parse

    # Build multipart form data
    boundary = "----BasiliskPolyglot" + os.urandom(8).hex()
    body_parts: list[str] = []
    body_parts.append(f'----{boundary}')
    body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"')
    body_parts.append(f"Content-Type: {content_type}")
    body_parts.append("")
    body_parts.append(file_data.decode(errors="replace") if file_data else "")
    body_parts.append(f"----{boundary}--")
    body = "\r\n".join(body_parts).encode(errors="replace")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }

    try:
        response = engine.send("POST", upload_url, headers=headers, data=body, timeout=timeout)
        if not response:
            return False, ["No response from server"]

        status = response.get("status_code", 0)
        body = response.get("body", "") or ""

        # Check if file was accepted
        accepted = status in (200, 201, 202, 203, 204, 301, 302, 303, 307, 308)

        evidence: list[str] = []
        if accepted:
            evidence.append(f"File accepted with status {status}")
            # Check if we can access the file via a different extension
            evidence.append("Server accepted file despite polyglot nature")
            return True, evidence
        else:
            evidence.append(f"File rejected with status {status}")
            # Try accessing with different extension
            return False, evidence

    except Exception as exc:
        logger.debug("Polyglot acceptance test failed: %s", exc)
        return False, [f"Test error: {exc}"]

    return False, ["Unknown result"]


def polyglot_upload_fuzzer(
    engine,
    upload_url: str,
    filename: str,
    file_data: bytes,
    content_type: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a file upload endpoint with polyglot files.

    Args:
        engine: RequestEngine instance.
        upload_url: The upload endpoint URL.
        filename: Filename to use.
        file_data: File data to upload.
        content_type: Content-Type header.
        timeout: Request timeout.

    Returns:
        List of Findings from polyglot upload fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Test polyglot acceptance
    accepted, evidence = detect_polyglot_acceptance(engine, upload_url, file_data, filename, content_type)

    if accepted:
        cvss, vector = score_finding("polyglot")
        findings.append(
            Finding(
                vulnerability="Polyglot file upload accepted",
                severity="High",
                description=f"Server accepted polyglot file ({'; '.join(evidence)})",
                target=upload_url,
                attack_type="polyglot",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate uploaded files using magic bytes and content analysis, "
                "not just filename and Content-Type. Reject files with conflicting type "
                "indicators.",
            )
        )
    else:
        cvss, vector = score_finding("polyglot")
        findings.append(
            Finding(
                vulnerability="Polyglot file upload rejected",
                severity="Low",
                description=f"Server rejected polyglot file: {'; '.join(evidence)}",
                target=upload_url,
                attack_type="polyglot",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Same as above - validate using magic bytes.",
            )
        )

    # Also test with different filename extensions
    base_name = os.path.splitext(filename)[0]
    for ext in [".php", ".exe", ".js", ".asp"]:
        test_filename = f"{base_name}{ext}"
        test_accepted, test_evidence = detect_polyglot_acceptance(engine, upload_url, file_data, test_filename, content_type)
        if test_accepted:
            findings.append(
                Finding(
                    vulnerability=f"Polyglot upload accepted as {ext}",
                    severity="High",
                    description=f"Server accepted file as {ext}: {'; '.join(test_evidence)}",
                    target=upload_url,
                    attack_type="polyglot",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Same as above - validate using magic bytes.",
                )

    return findings