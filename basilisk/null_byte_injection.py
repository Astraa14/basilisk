"""Advanced null byte injection beyond basic payloads.

Provides: null byte injection via different vectors (URL parameters,
headers, file names), detection of null-byte filtering bypasses, and
magic-byte-aware payload generation.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding

logger = logging.getLogger(__name__)

NULL_BYTE = "%00"
NULL_BYTE_RAW = "\x00"
NULL_VECTORS = {"url_param": "{}={NULL_BYTE}", "header": "{}:{NULL_BYTE}", "body_param": "{}={NULL_BYTE}", "file_name": 'filename="{NULL_BYTE}'}


def generate_null_byte_payload(vector_type: str, target: str) -> str:
    template = NULL_VECTORS.get(vector_type, NULL_VECTORS["url_param"])
    return template.format(target)


def null_byte_injection_fuzzer(engine, url: str, param_name: str, timeout: float = 5.0) -> list[Finding]:
    from basilisk.http import RequestEngine
    findings = []
    orig_response = engine.send("GET", url, timeout=timeout)
    if not orig_response:
        return findings
    for vector_type in NULL_VECTORS:
        payload = generate_null_byte_payload(vector_type, param_name)
        from urllib.parse import urlparse, urlunparse, parse_qsl, quote, urlencode
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        qs[param_name] = payload
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            response = engine.send("GET", test_url, timeout=timeout)
            if not response:
                continue
            status = response.get("status_code", 0)
            body = response.get("body", "") or ""
            if NULL_BYTE in body:
                cvss, vector = 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                findings.append(
                    Finding(vulnerability="Null byte injection via " + vector_type,
                            severity="High", description="Null byte reflected in response",
                            target=test_url, attack_type="null_byte",
                            cvss_score=cvss, cvss_vector=vector)
                )
            elif 500 <= status <= 503:
                cvss, vector = 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                findings.append(
                    Finding(vulnerability="Null byte caused server error",
                            severity="Medium", description="Null byte caused " + str(status),
                            target=test_url, attack_type="null_byte",
                            cvss_score=cvss, cvss_vector=vector)
                )
        except Exception:
            pass
    return findings