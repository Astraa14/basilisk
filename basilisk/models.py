"""Shared data models for Basilisk scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class AttackType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    LFI = "lfi"
    NOSQLI = "nosqli"
    LOGIN = "login"
    # Phase 2 — new detectors
    XXE = "xxe"
    GRAPHQL = "graphql"
    BOLA = "bola"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    SSTI_ADVANCED = "ssti_advanced"
    SSRF_OOB = "ssrf_oob"
    WEBSOCKET = "websocket"
    RACE_CONDITION = "race_condition"
    LDAP = "ldap"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    # Phase 3 — auth
    AUTH_BYPASS = "auth_bypass"
    CSRF = "csrf"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_STUFFING = "credential_stuffing"
    # Phase 4 — advanced
    WAF_DETECTION = "waf_detection"
    BLIND_SQLI = "blind_sqli"
    DOM_XSS = "dom_xss"
    PAYLOAD_CHAIN = "payload_chain"
    # Phase 5 — ML / intelligence
    ZERO_DAY = "zero_day"
    CONTAINER_ESCAPE = "container_escape"
    NETWORK_SEGMENTATION = "network_segmentation"
    API_ENUM = "api_enum"
    DEPENDENCY_CHECK = "dependency_check"
    # Phase 6 — specialized
    CMS = "cms"
    MOBILE_API = "mobile_api"
    COMPLIANCE = "compliance"
    VISUAL_REGRESSION = "visual_regression"


@dataclass
class Finding:
    vulnerability: str
    severity: str
    description: str
    target: str
    attack_type: str = ""
    payload: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: float = 1.0
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {}
        for k, v in asdict(self).items():
            if isinstance(v, list):
                if v:
                    d[k] = v
            elif v:
                d[k] = v
        return d


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
class ScanConfig:
    """Configuration for scan execution."""
    concurrency: int = 10
    adaptive: bool = False
    waf_evasion: bool = False
    deep_scan: bool = False
    max_pages: int = 15
    timeout: float = 5.0
    delay: float = 0.0
    max_retries: int = 1
    use_llm: bool = False
    use_ml: bool = False


@dataclass
class ScanReport:
    target: str
    pages_scanned: int = 0
    forms_found: int = 0
    vulnerable: bool = False
    findings: list[Finding] = field(default_factory=list)
    exploits_found: list[dict] = field(default_factory=list)
    mode: str = "static"
    scan_duration: float = 0.0
    config: ScanConfig | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_scanned": self.pages_scanned,
            "forms_found": self.forms_found,
            "vulnerable": self.vulnerable,
            "findings": [f.to_dict() for f in self.findings],
            "exploits_found": self.exploits_found,
            "mode": self.mode,
            "scan_duration": round(self.scan_duration, 2),
        }
