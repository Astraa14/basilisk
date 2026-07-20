"""ML-based vulnerability classifier — lightweight heuristic + pattern matching."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from basilisk.models import Finding


@dataclass
class ClassificationResult:
    attack_type: str
    confidence: float
    features: dict = field(default_factory=dict)
    similar_known: list[str] = field(default_factory=list)


class VulnerabilityClassifier:
    """Classify response + payload pairs into vulnerability types using heuristic feature extraction."""

    SIGNATURE_DB: dict[str, list[dict]] = {
        "sqli": [
            {"pattern": r"sql syntax.*mysql", "weight": 0.9},
            {"pattern": r"unclosed quotation mark", "weight": 0.85},
            {"pattern": r"sqlite3\.operationalerror", "weight": 0.9},
            {"pattern": r"odbc (driver|sql)", "weight": 0.8},
            {"pattern": r"postgresql.*error", "weight": 0.85},
            {"pattern": r"ora-\d{5}", "weight": 0.9},
            {"pattern": r"you have an error in your sql syntax", "weight": 0.95},
            {"pattern": r"warning: mysql", "weight": 0.7},
            {"pattern": r"cannot insert duplicate", "weight": 0.5},
        ],
        "xss": [
            {"pattern": r"<script>alert", "weight": 0.95},
            {"pattern": r"<img\s+src=.*onerror=", "weight": 0.9},
            {"pattern": r"<svg.*onload=", "weight": 0.85},
            {"pattern": r"onmouseover|onfocus|onclick=", "weight": 0.6},
            {"pattern": r"javascript:alert", "weight": 0.8},
        ],
        "cmdi": [
            {"pattern": r"uid=\d+\([\w-]+\)", "weight": 0.9},
            {"pattern": r"www-data|xfs|daemon|bin:", "weight": 0.7},
            {"pattern": r"linux version|microsoft windows", "weight": 0.6},
            {"pattern": r"total \d+\n", "weight": 0.5},
        ],
        "ssti": [
            {"pattern": r"49", "condition": lambda p: "{{7*7}}" in p or "${7*7}" in p, "weight": 0.9},
            {"pattern": r"config|__class__|__mro__|__subclasses__", "weight": 0.8},
            {"pattern": r"self\._TemplateReference", "weight": 0.7},
        ],
        "path_traversal": [
            {"pattern": r"root:.*:0:", "weight": 0.9},
            {"pattern": r"dr[-\[][\w-]{9}", "weight": 0.6},
            {"pattern": r"\[extensions\]", "weight": 0.7},
        ],
        "ssrf": [
            {"pattern": r"ami-id|instance-id", "weight": 0.9},
            {"pattern": r"security-credentials", "weight": 0.8},
            {"pattern": r"meta-data", "weight": 0.7},
            {"pattern": r"ec2.*amazon", "weight": 0.5},
        ],
    }

    def __init__(self, known_findings_path: str | Path | None = None):
        self._known_patterns: dict[str, list[str]] = {}
        if known_findings_path:
            self._load_known_findings(known_findings_path)

    def _load_known_findings(self, path: str | Path) -> None:
        try:
            data = json.loads(Path(path).read_text())
            for entry in data:
                at = entry.get("attack_type", "")
                body = entry.get("body", "")
                if at and body:
                    self._known_patterns.setdefault(at, []).append(body[:200])
        except Exception:
            pass

    def classify(self, payload: str, response_body: str) -> ClassificationResult:
        """Classify a payload+response pair into the most likely vulnerability type."""
        lower_body = response_body.lower()
        scores: dict[str, float] = {}

        for attack_type, signatures in self.SIGNATURE_DB.items():
            score = 0.0
            matches = 0
            for sig in signatures:
                condition = sig.get("condition")
                if condition and not condition(payload):
                    continue
                if re.search(sig["pattern"], lower_body, re.I):
                    score += sig["weight"]
                    matches += 1

            if matches > 0:
                scores[attack_type] = score / max(matches, 1)

        # Similarity to known findings
        for attack_type, bodies in self._known_patterns.items():
            payload_hash = hashlib.md5(payload.encode()).hexdigest()
            for known_body in bodies:
                known_hash = hashlib.md5(known_body.encode()).hexdigest()
                if payload_hash[:6] == known_hash[:6]:
                    scores[attack_type] = scores.get(attack_type, 0) + 0.3

        if not scores:
            return ClassificationResult(
                attack_type="unknown",
                confidence=0.0,
                features={"payload_length": len(payload), "body_length": len(response_body)},
            )

        best = max(scores, key=scores.get)
        best_score = scores[best]
        normalized = min(best_score / 0.95, 1.0)

        similar_known = [
            at for at, s in scores.items() if s >= best_score * 0.8 and at != best
        ]

        return ClassificationResult(
            attack_type=best,
            confidence=normalized,
            features={at: round(s, 3) for at, s in sorted(scores.items(), key=lambda x: -x[1])},
            similar_known=similar_known,
        )

    def rank_findings(self, findings: list[Finding]) -> list[Finding]:
        """Rank findings by severity, CVSS score, and confidence."""
        def sort_key(f: Finding) -> tuple:
            sev = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
            return (sev.get(f.severity, 0), f.cvss_score, f.confidence)

        return sorted(findings, key=sort_key, reverse=True)


def extract_features(response: dict, payload: str) -> dict:
    """Extract numerical features from a response for ML classification."""
    body = response.get("body", "")
    headers = response.get("headers", {})

    return {
        "status_code": response.get("status_code", 0),
        "body_length": len(body),
        "payload_length": len(payload),
        "header_count": len(headers),
        "has_error": int(any(e in body.lower() for e in ["error", "exception", "fatal"])),
        "has_sql_error": int(any(e in body.lower() for e in ["sql", "mysql", "sqlite"])),
        "has_reflection": int(payload[:50] in body),
        "is_json": int(bool(body.startswith("{")) or bool(body.startswith("["))),
    }
