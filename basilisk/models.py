"""Shared data models for Basilisk scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    vulnerability: str
    severity: str
    description: str
    target: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackAttempt:
    strategy: str
    payload: str
    endpoint: str
    method: str
    status_code: int | None = None
    vulnerable: bool = False
    reason: str = ""


@dataclass
class ScanReport:
    target: str
    pages_scanned: int = 0
    forms_found: int = 0
    vulnerable: bool = False
    findings: list[Finding] = field(default_factory=list)
    exploits_found: list[dict] = field(default_factory=list)
    mode: str = "static"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_scanned": self.pages_scanned,
            "forms_found": self.forms_found,
            "vulnerable": self.vulnerable,
            "findings": [f.to_dict() for f in self.findings],
            "exploits_found": self.exploits_found,
            "mode": self.mode,
        }
