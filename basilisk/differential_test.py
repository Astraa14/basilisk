"""Differential testing — compare responses between production and staging environments."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding


@dataclass
class DiffResult:
    endpoint: str = ""
    prod_hash: str = ""
    staging_hash: str = ""
    prod_status: int = 0
    staging_status: int = 0
    prod_size: int = 0
    staging_size: int = 0
    differences: list[str] = field(default_factory=list)
    is_different: bool = False


@dataclass
class DifferentialAnalysis:
    results: list[DiffResult] = field(default_factory=list)
    identical_count: int = 0
    different_count: int = 0
    findings: list[Finding] = field(default_factory=list)


SENSITIVE_DIFF_MARKERS = [
    "api_key", "api.secret", "password", "token", "jwt",
    "internal_ip", "10.", "192.168.", "172.16.",
    "debug", "stack_trace", "traceback", "internal_error",
    ".env", ".git", "database_url", "DATABASE_URL",
    "secret_key", "secret", "private_key",
]


class DifferentialTester:
    """Compare production and staging environments for security drift."""

    def __init__(self, prod_fn: Callable | None = None, staging_fn: Callable | None = None):
        self.prod_fn = prod_fn
        self.staging_fn = staging_fn

    def compare(
        self,
        endpoints: list[str],
        prod_base: str = "",
        staging_base: str = "",
    ) -> DifferentialAnalysis:
        analysis = DifferentialAnalysis()

        for ep in endpoints:
            prod_url = f"{prod_base.rstrip('/')}{ep}" if prod_base else ep
            staging_url = f"{staging_base.rstrip('/')}{ep}" if staging_base else ep

            prod_resp = self.prod_fn({"url": prod_url}) if self.prod_fn else None
            staging_resp = self.staging_fn({"url": staging_url}) if self.staging_fn else None

            if not prod_resp and not staging_resp:
                continue
            if not prod_resp or not staging_resp:
                diff = DiffResult(endpoint=ep, is_different=True)
                diff.prod_status = prod_resp.get("status_code", 0) if prod_resp else 0
                diff.staging_status = staging_resp.get("status_code", 0) if staging_resp else 0
                analysis.results.append(diff)
                analysis.different_count += 1
                continue

            prod_body = prod_resp.get("body", "")
            staging_body = staging_resp.get("body", "")
            prod_hash = hashlib.md5(prod_body.encode()).hexdigest()[:16]
            staging_hash = hashlib.md5(staging_body.encode()).hexdigest()[:16]

            diff = DiffResult(
                endpoint=ep,
                prod_hash=prod_hash,
                staging_hash=staging_hash,
                prod_status=prod_resp.get("status_code", 0),
                staging_status=staging_resp.get("status_code", 0),
                prod_size=len(prod_body),
                staging_size=len(staging_body),
            )

            if prod_hash != staging_hash:
                diff.is_different = True
                analysis.different_count += 1
                self._analyze_differences(diff, prod_body, staging_body)
            else:
                analysis.identical_count += 1

            analysis.results.append(diff)

        return analysis

    def _analyze_differences(self, diff: DiffResult, prod: str, staging: str) -> None:
        if diff.prod_status != diff.staging_status:
            diff.differences.append(
                f"Status code mismatch: prod={diff.prod_status} staging={diff.staging_status}"
            )

        if abs(diff.prod_size - diff.staging_size) > 1000:
            diff.differences.append(
                f"Size difference: prod={diff.prod_size}b staging={diff.staging_size}b "
                f"({abs(diff.prod_size - diff.staging_size)}b delta)"
            )

        for marker in SENSITIVE_DIFF_MARKERS:
            if (marker in staging.lower()) != (marker in prod.lower()):
                diff.differences.append(
                    f"Content diff: '{marker}' present in one environment but not the other"
                )

    def to_findings(self, analysis: DifferentialAnalysis, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for diff in analysis.results:
            if not diff.differences:
                continue
            cvss, vector = score_finding("info_disclosure")
            findings.append(
                Finding(
                    vulnerability="Differential: Environment Mismatch",
                    severity="Medium",
                    description=f"Endpoint {diff.endpoint} differs between environments: {'; '.join(diff.differences[:3])}",
                    target=target,
                    attack_type="info_disclosure",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    confidence=0.5,
                    remediation="Ensure staging configuration mirrors production. Use env-specific configs.",
                )
            )
        return findings
