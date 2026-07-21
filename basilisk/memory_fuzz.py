"""Memory corruption detection via fuzzing instrumentation."""

from __future__ import annotations

import logging
import random
import string
import struct
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

CORRUPTION_PAYLOADS = [
    {"name": "Null byte flood", "payload": "\x00" * 1000},
    {"name": "Format string", "payload": "%x%x%x%x%x%x%x%x%n%n%n%n"},
    {"name": "Buffer overflow", "payload": "A" * 10000},
    {"name": "Integer overflow", "payload": "99999999999999999999999999999999999999"},
    {"name": "Negative number", "payload": "-99999999999999999999"},
    {"name": "Unicode flood", "payload": "\uFFFE\uFFFD" * 500},
    {"name": "Control chars", "payload": "".join(chr(i) for i in range(32))},
    {"name": "Long path", "payload": "/" * 10000 + "etc/passwd"},
    {"name": "Float special", "payload": "NaNInfinity-Infinity1.0e+9999"},
    {"name": "Binary garbage", "payload": bytes(random.randint(0, 255) for _ in range(500)).decode("latin-1")},
    {"name": "Deeply nested JSON", "payload": "{" * 1000 + "}" * 1000},
    {"name": "Very large number", "payload": "1" * 10000},
]

CRASH_SIGNATURES = [
    "segmentation fault", "segfault", "SIGSEGV",
    "access violation", "access violation reading",
    "bus error", "SIGBUS", "stack overflow",
    "stack smashing", "corrupted", "double free",
    "heap corruption", "buffer overflow", "abort()",
    "signal 11", "signal 6", "signal 4",
    "out of memory", "cannot allocate memory",
    "NullReferenceException", "NullPointerException",
    "StackOverflowError", "OutOfMemoryError",
    "IndexOutOfBoundsException",
]

MEMORY_CORRUPTION_HEADERS = [
    "Content-Length: -1",
    "Content-Length: 9999999999",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Expect: " + "A" * 10000,
    "Cookie: " + "A" * 10000,
    "X-Forwarded-For: " + "A" * 1000,
]


@dataclass
class MemoryCorruptionTest:
    name: str
    payload_type: str
    payload: str


@dataclass
class FuzzResult:
    test_name: str = ""
    crashed: bool = False
    status_code: int = 0
    crash_signal: str = ""
    body_preview: str = ""
    findings: list[Finding] = field(default_factory=list)


class MemoryFuzzer:
    """Fuzz endpoints for memory corruption and crash indicators."""

    def __init__(self, fetch_fn=None):
        self.fetch_fn = fetch_fn

    def fuzz(self, target_url: str) -> list[FuzzResult]:
        results: list[FuzzResult] = []
        if not self.fetch_fn:
            return results

        for test in self._generate_tests():
            try:
                resp = self.fetch_fn({
                    "url": target_url,
                    "method": "POST",
                    "body": test.payload,
                    "headers": {"Content-Type": "text/plain"},
                    "fuzz_test": True,
                })
                if resp:
                    result = self._analyze_response(resp, test)
                    results.append(result)
            except Exception as e:
                logger.debug("Fuzz test '%s' failed: %s", test.name, e)
                results.append(FuzzResult(
                    test_name=test.name,
                    crashed=True,
                    crash_signal=str(e)[:100],
                ))

        return results

    def fuzz_headers(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        if not self.fetch_fn:
            return findings

        for header_line in MEMORY_CORRUPTION_HEADERS:
            try:
                name, value = header_line.split(": ", 1) if ": " in header_line else ("X-Test", header_line)
                resp = self.fetch_fn({
                    "url": target_url,
                    "method": "GET",
                    "headers": {name: value},
                    "fuzz_test": True,
                })
                if resp:
                    body = resp.get("body", "")
                    status = resp.get("status_code", 0)
                    lower_body = body.lower()
                    for sig in CRASH_SIGNATURES:
                        if sig in lower_body:
                            cvss, vector = score_finding("zero_day")
                            findings.append(
                                Finding(
                                    vulnerability="Memory Corruption via Header Fuzzing",
                                    severity="High",
                                    description=f"Header '{name}' triggered crash signal '{sig}'. HTTP {status}.",
                                    target=target_url,
                                    attack_type="memory_corruption",
                                    payload=f"{name}: {value[:60]}",
                                    cvss_score=cvss,
                                    cvss_vector=vector,
                                    remediation="Validate and sanitize all header inputs. Use safe string handling libraries.",
                                )
                            )
                            break
            except Exception:
                continue

        return findings

    def _generate_tests(self) -> list[MemoryCorruptionTest]:
        tests: list[MemoryCorruptionTest] = []
        for entry in CORRUPTION_PAYLOADS:
            tests.append(MemoryCorruptionTest(
                name=entry["name"],
                payload_type=entry["name"],
                payload=entry["payload"],
            ))
        return tests

    def _analyze_response(self, resp: dict, test: MemoryCorruptionTest) -> FuzzResult:
        body = resp.get("body", "")
        status = resp.get("status_code", 0)
        lower_body = body.lower()

        result = FuzzResult(test_name=test.name, status_code=status)

        for sig in CRASH_SIGNATURES:
            if sig in lower_body:
                result.crashed = True
                result.crash_signal = sig
                result.body_preview = body[:200]
                cvss, vector = score_finding("zero_day")
                result.findings.append(
                    Finding(
                        vulnerability=f"Memory Corruption: {test.name}",
                        severity="Critical" if status in (0, 500) else "High",
                        description=f"Crash signal '{sig}' triggered by {test.name} payload. HTTP {status}.",
                        target=resp.get("url", ""),
                        attack_type="memory_corruption",
                        payload=test.payload[:80],
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Use memory-safe languages or libraries. Implement bounds checking on all buffers.",
                    )
                )
                break

        if status == 500 and len(body) > 0:
            cvss, vector = score_finding("zero_day")
            result.findings.append(
                Finding(
                    vulnerability=f"Server Crash: {test.name}",
                    severity="High",
                    description=f"HTTP 500 triggered by {test.name} payload. Possible memory corruption.",
                    target=resp.get("url", ""),
                    attack_type="memory_corruption",
                    payload=test.payload[:80],
                    cvss_score=cvss,
                    cvss_vector=vector,
                    confidence=0.5,
                )
            )

        return result


def get_corruption_payloads() -> list[dict]:
    return list(CORRUPTION_PAYLOADS)

def get_crash_signatures() -> list[str]:
    return list(CRASH_SIGNATURES)
