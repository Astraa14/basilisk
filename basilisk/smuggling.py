"""HTTP request smuggling detection via protocol state machine analysis."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

CL_TE_PAYLOADS = [
    {"name": "CL-TE basic", "headers": {"Content-Length": "13", "Transfer-Encoding": "chunked"}, "body": "0\r\n\r\nG"},
    {"name": "CL-TE with prefix", "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"}, "body": "65\r\nGPOST"},
    {"name": "CL-TE double", "headers": {"Content-Length": "6", "Transfer-Encoding": ["chunked", "x"]}, "body": "0\r\n\r\nX"},
]

TE_CL_PAYLOADS = [
    {"name": "TE-CL basic", "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"}, "body": "5c\r\nGPOST"},
    {"name": "TE-CL obfuscated", "headers": {"Transfer-Encoding": "xchunked", "Content-Length": "4"}, "body": "0\r\n\r\n"},
]

TE_TE_PAYLOADS = [
    {"name": "TE-TE obfuscated", "headers": {"Transfer-Encoding": ["chunked", "x"]}, "body": "0\r\n\r\nGPOST"},
    {"name": "TE-TE tab", "headers": {"Transfer-Encoding": "\tchunked"}, "body": "0\r\n\r\nGPOST"},
]

PROTOCOL_VIOLATIONS = [
    {"name": "Duplicate Content-Length", "pattern": r"Content-Length:.*\n.*Content-Length:"},
    {"name": "CL + TE together", "pattern": r"Content-Length:.*\n.*Transfer-Encoding:"},
    {"name": "Chunked with Content-Length", "pattern": r"Transfer-Encoding:.*\n.*Content-Length:"},
    {"name": "Line folding", "pattern": r"\r\n\s+[a-zA-Z]"},
    {"name": "Null byte injection", "pattern": r"\x00"},
]


@dataclass
class SmuggleTest:
    name: str
    headers: dict
    body: str
    expected_discrepancy: str = ""


@dataclass
class SmuggleResult:
    vulnerable: bool = False
    technique: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    findings: list[Finding] = field(default_factory=list)


class SmuggleDetector:
    """HTTP request smuggling detection via discrepant response analysis."""

    def __init__(self, target_fn=None):
        self.target_fn = target_fn

    def detect(self, base_url: str) -> SmuggleResult:
        result = SmuggleResult()
        if not self.target_fn:
            return result

        for test in self._all_tests():
            try:
                response1 = self.target_fn({
                    "url": base_url,
                    "method": "POST",
                    "headers": test.headers,
                    "body": test.body,
                    "smuggle_test": True,
                })
                response2 = self.target_fn({
                    "url": base_url,
                    "method": "GET",
                    "smuggle_test": True,
                })

                if response1 and response2:
                    self._analyze_responses(response1, response2, test, result)
            except Exception as e:
                logger.debug("Smuggle test %s failed: %s", test.name, e)

        return result

    def _all_tests(self) -> list[SmuggleTest]:
        tests: list[SmuggleTest] = []
        for t in CL_TE_PAYLOADS:
            tests.append(SmuggleTest(name=t["name"], headers=t["headers"], body=t["body"]))
        for t in TE_CL_PAYLOADS:
            tests.append(SmuggleTest(name=t["name"], headers=t["headers"], body=t["body"]))
        for t in TE_TE_PAYLOADS:
            tests.append(SmuggleTest(name=t["name"], headers=t["headers"], body=t["body"]))
        return tests

    def _analyze_responses(self, r1: dict, r2: dict, test: SmuggleTest, result: SmuggleResult) -> None:
        body1 = r1.get("body", "")
        body2 = r2.get("body", "")
        status1 = r1.get("status_code", 0)
        status2 = r2.get("status_code", 0)

        anomalies = []

        if status2 == 400 and "bad request" in body2.lower():
            anomalies.append(f"Second request returned 400 — possible desync")
            result.confidence = max(result.confidence, 0.4)

        if body2 and ("unexpected" in body2.lower() or "error" in body2.lower()):
            anomalies.append(f"Second request body contains error after smuggle payload")
            result.confidence = max(result.confidence, 0.5)

        if "502" in str(r2.get("headers", {}).get(":status", "")):
            anomalies.append("Backend connection reset — possible buffer desync")
            result.confidence = max(result.confidence, 0.6)

        if anomalies:
            result.vulnerable = True
            result.technique = test.name
            result.evidence.extend(anomalies)

    def analyze_raw_headers(self, raw_headers: str) -> list[Finding]:
        findings: list[Finding] = []
        for v in PROTOCOL_VIOLATIONS:
            if re.search(v["pattern"], raw_headers, re.MULTILINE):
                cvss, vector = score_finding("ssrf")
                findings.append(
                    Finding(
                        vulnerability=f"HTTP Protocol Violation: {v['name']}",
                        severity="Medium",
                        description=f"Raw header analysis detected: {v['name']}",
                        attack_type="smuggling",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Use a proper HTTP parser library. Validate and normalize all incoming headers.",
                    )
                )
        return findings

    def static_analyze(self, raw_request: str) -> SmuggleResult:
        result = SmuggleResult()
        cl_count = len(re.findall(r"Content-Length:", raw_request, re.I))
        te_count = len(re.findall(r"Transfer-Encoding:", raw_request, re.I))

        if cl_count > 1:
            result.vulnerable = True
            result.technique = "Duplicate Content-Length"
            result.evidence.append(f"Found {cl_count} Content-Length headers")
            result.confidence = 0.7

        if cl_count >= 1 and te_count >= 1:
            result.vulnerable = True
            result.technique = "CL.TE mismatch"
            result.evidence.append("Both Content-Length and Transfer-Encoding present")
            result.confidence = 0.6

        return result


def get_smuggle_payloads() -> list[dict]:
    return CL_TE_PAYLOADS + TE_CL_PAYLOADS + TE_TE_PAYLOADS

def get_protocol_violations() -> list[dict]:
    return list(PROTOCOL_VIOLATIONS)
