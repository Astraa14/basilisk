"""MIME type confusion vulnerability detection.

Detects situations where a server's MIME type handling allows one file type
to be interpreted as another, enabling file upload bypasses, execution, or
confusion-based attacks.
"""

from __future__ import annotations

import logging
import mimetypes
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Common MIME type confusion vectors
CONFUSION_VECTORS: list[dict] = [
    {
        "extension": ".php",
        "spoofed_type": "image/jpeg",
        "description": "Upload .php file with image/jpeg Content-Type to execute code",
    },
    {
        "extension": ".exe",
        "spoofed_type": "image/png",
        "description": "Upload executable with image/png to bypass filters",
    },
    {
        "extension": ".asp",
        "spoofed_type": "text/plain",
        "description": "Active Server Page with text/plain Content-Type",
    },
    {
        "extension": ".js",
        "spoofed_type": "text/css",
        "description": "JavaScript file served as CSS (some parsers execute)",
    },
]

# File extensions that are potentially dangerous when MIME types are ignored
DANGEROUS_EXTENSIONS: list[str] = [
    ".php",
    ".phtml",
    ".php5",
    ".asp",
    ".aspx",
    ".jsp",
    ".rb",
    ".pl",
    ".py",
    ".sh",
    ".cmd",
    ".exe",
    ".dll",
    ".bin",
]

# Extensions that are generally safe
SAFE_EXTENSIONS: list[str] = [
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".txt",
    ".html",
    ".htm",
    ".css",
    ".json",
    ".xml",
]


def detect_mime_confusion(
    filename: str,
    content_type: str,
    expected_type: str | None = None,
) -> tuple[bool, list[str]]:
    """Detect potential MIME type confusion for a file upload.

    Args:
        filename: The uploaded filename.
        content_type: The Content-Type header provided by the client.
        expected_type: Expected Content-Type (e.g., from server validation).

    Returns:
        (is_confusion, evidence) evidence list.
    """
    is_confusion = False
    evidence: list[str] = []

    # Parse the file extension
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    ext = "." + ext

    # Check if the file has a dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        is_confusion = True
        evidence.append(f"File has dangerous extension: {ext}")

    # Check if the Content-Type matches the extension
    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and content_type:
        # Normalize both for comparison
        guessed_norm = guessed_type.lower().replace(" ", "")
        content_norm = content_type.lower().replace(" ", "")

        # If the provided Content-Type is different from what's guessed
        # from the filename, that's a confusion vector
        if content_norm != guessed_norm:
            is_confusion = True
            evidence.append(
                f"MIME type confusion: client sent '{content_type}', "
                f"guessed from filename as '{guessed_type}'"
            )

        # If the content type is a spoofed type for the extension
        for vector in CONFUSION_VECTORS:
            if ext == vector["extension"] and content_type == vector["spoofed_type"]:
                is_confusion = True
                evidence.append(
                    f"MIME confusion vector: '{ext}' uploaded as '{content_type}' "
                    f"(expected type for extension: implicit or {vector['description']})"
                )

    # If no explicit content type, but extension is dangerous
    if not content_type and ext in DANGEROUS_EXTENSIONS:
        is_confusion = True
        evidence.append(
            f"No Content-Type provided for dangerous file extension: {ext}"
        )

    return is_confusion, evidence


def mime_confusion_fuzzer(
    engine,
    url: str,
    filename: str,
    content_type: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a file upload with MIME type confusion payloads.

    Args:
        engine: RequestEngine instance.
        url: Upload endpoint URL.
        filename: Uploaded filename.
        content_type: Content-Type header value.
        timeout: Request timeout.

    Returns:
        List of Findings from MIME type confusion fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    is_confusion, evidence = detect_mime_confusion(filename, content_type)

    if is_confusion:
        cvss, vector = score_finding("mime_conf")
        findings.append(
            Finding(
                vulnerability="MIME type confusion in file upload",
                severity="High" if any("execute" in e.lower() for e in evidence) else "Medium",
                description=f"MIME type confusion detected: {'; '.join(evidence)}",
                target=url,
                attack_type="mime_conf",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate MIME types server-side based on actual file content "
                "(magic bytes), not solely on client-provided Content-Type headers. "
                "Use allowlists of permitted types.",
            )
        )
    else:
        # Log as info - no confusion detected
        cvss, vector = score_finding("mime_conf")
        findings.append(
            Finding(
                vulnerability="No MIME type confusion detected",
                severity="Info",
                description="No MIME type confusion detected - file upload validation appears correct",
                target=url,
                attack_type="mime_conf",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Continue validating MIME types based on content magic bytes.",
            )
        )

    return findings


def magic_byte_detection(
    content: bytes,
    expected_type: str,
) -> tuple[bool, list[str]]:
    """Detect magic byte (file signature) mismatches.

    Compares the actual file content magic bytes against the expected type.

    Args:
        content: Raw file bytes.
        expected_type: Expected MIME type.

    Returns:
        (is_mismatch, evidence) evidence list.
    """
    is_mismatch = False
    evidence: list[str] = []

    # Magic byte signatures for common types
    magic_bytes: dict[str, bytes] = {
        ".jpg": b"\xff\xd8\xff",
        ".jpeg": b"\xff\xd8\xff",
        ".png": b"\x89PNG\r\n\x1a\n",
        ".gif": b"GIF87a" or b"GIF89a",
        ".pdf": b"%PDF",
        ".zip": b"PK\x03\x04",
        ".rar": b"Rar!",
        ".exe": b"\x90\x00\x00\x00" or b"MZ",
        ".doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        ".xls": b"D0CF11E0",
        ".docx": b"PK\x03\x04",
        ".ppt": b"D0CF11E0",
    }

    # Find the matching magic byte
    for ext, sig in magic_bytes.items():
        if content.startswith(sig):
            # Check if the expected type matches
            expected_map: dict[str, str] = {
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".png": "image/png",
                ".gif": "image/gif",
                ".pdf": "application/pdf",
                ".zip": "application/zip",
                ".exe": "application/octet-stream",
                ".doc": "application/msword",
                ".xls": "application/vnd.ms-excel",
                ".ppt": "application/vnd.ms-powerpoint",
            }
            expected = expected_map.get(ext)
            if expected and expected.lower() != expected_type.lower():
                is_mismatch = True
                evidence.append(
                    f"Magic byte {sig.hex()} indicates {ext} but "
                    f"Content-Type is '{expected_type}' (expected {expected})"
                )
            elif expected:
                evidence.append(
                    f"Magic byte {sig.hex()} matches expected type {expected}"
                )
            break

    # If no magic byte matched, check if content type is suspicious
    if not is_mismatch and content_type:
        # Common mismatches: text/* for binary files
        if "/" in content_type and "/" in expected_type:
            primary, secondary = content_type.split("/", 1), expected_type.split("/", 1)
            if primary == "text" and secondary not in ("plain", "html"):
                is_mismatch = True
                evidence.append(
                    f"Content-Type '{content_type}' is text-type but file has binary magic bytes"
                )

    return is_mismatch, evidence


def mime_type_confusion_fuzzer(
    engine,
    url: str,
    file_data: bytes,
    filename: str,
    expected_content_type: str,
    timeout: float = 5.0,
) -> list[Finding]:
    """Fuzz a file upload with MIME type and magic byte manipulation.

    Args:
        engine: RequestEngine instance.
        url: Upload endpoint URL.
        file_data: Raw file bytes to upload.
        filename: Filename to use in the upload.
        expected_content_type: Expected Content-Type header.
        timeout: Request timeout.

    Returns:
        List of Findings from MIME type and magic byte fuzzing.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []

    # Detection 1: MIME type confusion
    mime_findings = mime_confusion_fuzzer(engine, url, filename, expected_content_type)
    findings.extend(mime_findings)

    # Detection 2: Magic byte analysis
    is_mismatch, evidence = magic_byte_detection(file_data, expected_content_type)
    if is_mismatch:
        cvss, vector = score_finding("magic_byte")
        findings.append(
            Finding(
                vulnerability="Magic byte / Content-Type mismatch",
                severity="High",
                description=f"Magic byte/content-type mismatch: {'; '.join(evidence)}",
                target=url,
                attack_type="magic_byte",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate file content using magic bytes server-side, not "
                "solely on client-provided Content-Type headers.",
            )
        )

    return findings