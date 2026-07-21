"""Behavioral anomaly detection — baseline traffic analysis for unusual patterns."""

from __future__ import annotations

import json
import statistics
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding


@dataclass
class BaselineMetric:
    min_val: float = 0.0
    max_val: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    stdev: float = 0.0
    p95: float = 0.0
    p99: float = 0.0


@dataclass
class BaselineProfile:
    response_times: BaselineMetric = field(default_factory=BaselineMetric)
    response_sizes: BaselineMetric = field(default_factory=BaselineMetric)
    status_code_distribution: dict[int, int] = field(default_factory=dict)
    content_type_counts: dict[str, int] = field(default_factory=dict)
    total_requests: int = 0
    anomaly_threshold: float = 3.0


@dataclass
class AnomalyEvent:
    endpoint: str = ""
    metric: str = ""
    expected_value: float = 0.0
    actual_value: float = 0.0
    deviation: float = 0.0
    description: str = ""


@dataclass
class BehavioralAnalysisResult:
    baseline: BaselineProfile = field(default_factory=BaselineProfile)
    anomalies: list[AnomalyEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class BehavioralAnalyzer:
    """Build baseline traffic profile and detect behavioral anomalies."""

    def __init__(self):
        self.baseline = BaselineProfile()
        self.anomaly_threshold = 3.0

    def build_baseline(self, responses: list[dict]) -> BaselineProfile:
        if not responses:
            return self.baseline

        times = []
        sizes = []
        statuses: Counter = Counter()
        content_types: Counter = Counter()

        for resp in responses:
            if resp:
                elapsed = resp.get("elapsed_time", 0)
                if elapsed > 0:
                    times.append(elapsed)
                sizes.append(len(resp.get("body", "")))
                statuses[resp.get("status_code", 0)] += 1
                ct = resp.get("headers", {}).get("Content-Type", resp.get("headers", {}).get("content-type", "unknown"))
                content_types[ct] += 1

        self.baseline = BaselineProfile(
            response_times=self._compute_metric(times),
            response_sizes=self._compute_metric(sizes),
            status_code_distribution=dict(statuses),
            content_type_counts=dict(content_types),
            total_requests=len(responses),
        )
        return self.baseline

    def _compute_metric(self, values: list[float]) -> BaselineMetric:
        if not values:
            return BaselineMetric()
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        return BaselineMetric(
            min_val=min(values),
            max_val=max(values),
            mean=statistics.mean(values),
            median=statistics.median(values) if n > 1 else values[0],
            stdev=statistics.stdev(values) if n > 1 else 0,
            p95=sorted_vals[int(n * 0.95)],
            p99=sorted_vals[int(n * 0.99)],
        )

    def detect_anomalies(self, new_responses: list[dict], base_url: str = "") -> BehavioralAnalysisResult:
        result = BehavioralAnalysisResult()
        result.baseline = self.baseline

        if not self.baseline.total_requests:
            return result

        for resp in new_responses:
            if not resp:
                continue
            url = resp.get("url", base_url)
            elapsed = resp.get("elapsed_time", 0)
            size = len(resp.get("body", ""))
            status = resp.get("status_code", 0)

            if elapsed > 0 and self.baseline.response_times.stdev > 0:
                z_score = (elapsed - self.baseline.response_times.mean) / max(self.baseline.response_times.stdev, 0.001)
                if abs(z_score) > self.anomaly_threshold:
                    result.anomalies.append(AnomalyEvent(
                        endpoint=url,
                        metric="response_time",
                        expected_value=self.baseline.response_times.mean,
                        actual_value=elapsed,
                        deviation=z_score,
                        description=f"Response time anomaly: {elapsed:.2f}s vs baseline {self.baseline.response_times.mean:.2f}s (z={z_score:.1f})",
                    ))

            if self.baseline.response_sizes.stdev > 0:
                z_size = (size - self.baseline.response_sizes.mean) / max(self.baseline.response_sizes.stdev, 0.001)
                if abs(z_size) > self.anomaly_threshold:
                    result.anomalies.append(AnomalyEvent(
                        endpoint=url,
                        metric="response_size",
                        expected_value=self.baseline.response_sizes.mean,
                        actual_value=float(size),
                        deviation=z_size,
                        description=f"Response size anomaly: {size}b vs baseline {self.baseline.response_sizes.mean:.0f}b (z={z_size:.1f})",
                    ))

            if status == 500:
                result.anomalies.append(AnomalyEvent(
                    endpoint=url, metric="status_code",
                    expected_value=200, actual_value=500, deviation=300,
                    description=f"Unexpected HTTP 500 at {url}",
                ))

        result.findings = self._anomalies_to_findings(result.anomalies, base_url)
        return result

    def _anomalies_to_findings(self, anomalies: list[AnomalyEvent], target: str) -> list[Finding]:
        findings: list[Finding] = []
        for anomaly in anomalies:
            cvss, vector = score_finding("zero_day")
            findings.append(
                Finding(
                    vulnerability="Behavioral Anomaly Detected",
                    severity="Medium" if anomaly.deviation > 5 else "Low",
                    description=f"{anomaly.description}",
                    target=anomaly.endpoint or target,
                    attack_type="zero_day",
                    confidence=min(abs(anomaly.deviation) / 10, 0.8),
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Investigate the anomalous request — may indicate scanning, misconfiguration, or attack.",
                )
            )
        return findings

    def detect_logic_bomb(self, response: dict, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        body = response.get("body", "")
        lower = body.lower()

        bomb_indicators = [
            "deleted", "removed", "terminated", "expired",
            "condition_met", "trigger_executed",
            "if date >= ", "if current_date",
            "time_bomb", "logic_bomb",
        ]
        for indicator in bomb_indicators:
            if indicator in lower:
                cvss, vector = score_finding("zero_day")
                findings.append(
                    Finding(
                        vulnerability="Potential Logic/Time Bomb Indicator",
                        severity="Critical",
                        description=f"Suspicious keyword '{indicator}' found in response. May indicate logic bomb or time bomb trigger.",
                        target=target,
                        attack_type="zero_day",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        confidence=0.3,
                        remediation="Audit code for conditional destructive operations gated by date or state checks.",
                    )
                )
        return findings
