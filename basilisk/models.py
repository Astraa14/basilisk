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
    # Division 1 — protocol & transport layer
    DNS_POISONING = "dns_poisoning"
    DNS_REBINDING = "dns_rebinding"
    TLS = "tls"
    ALPN = "alpn"
    HTTP2_PUSH = "http2_push"
    PIPELINING = "pipelining"
    REDIRECT_LOOP = "redirect_loop"
    TCP_ANOMALY = "tcp_anomaly"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"

    # Division 2 — attack vector & parameter fuzzing
    HTTP_PARAM_POLLUTION = "httppol"
    HEADER_INJECTION = "header_inj"
    HOST_HEADER_INJECTION = "host_inj"
    REQUEST_SPLITTING = "req_split"
    RESPONSE_SPLITTING = "resp_split"
    MIME_CONFUSION = "mime_conf"
    NULL_BYTE_INJECTION = "null_byte"
    POLYGLOT_FILE = "polyglot"
    MAGIC_BYTE = "magic_byte"


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
    # Division 1 — protocol & transport layer
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10
    backoff_factor: float = 1.0
    backoff_max: float = 30.0
    proxy: str | None = None
    no_proxy: list[str] = field(default_factory=list)
    pool_connections: int = 10
    pool_maxsize: int = 20
    cookie_jar: str = ""
    auth_method: str = "none"
    auth_token: str = ""
    auth_api_key: str = ""
    auth_api_key_name: str = "X-API-Key"
    auth_api_key_in: str = "header"
    auth_basic_user: str = ""
    auth_basic_password: str = ""
    oauth_token_url: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_scope: str = ""
    enable_http2: bool = True
    enable_http3: bool = False
    protocol_scan: bool = True
    dns_rebinding_check: bool = True
    pipeline_check: bool = True
    # Division 3: Web Security & Standards Violations
    http_smuggling: bool = True
    protocol_confusion: bool = True
    range_abuse: bool = True
    track_method: bool = True
    options_enum: bool = True
    webdav: bool = True
    csp_analysis: bool = True
    cors_misconfiguration: bool = True
    sri_bypass: bool = True
    service_worker: bool = True
    cache_control: bool = True
    hsts_preload: bool = True
    content_encoding_bypass: bool = True
    accept_encoding_manipulation: bool = True
    alternate_protocol: bool = True
    tcp_anomaly_check: bool = True
    request_logging: bool = False
    log_path: str = ""
    ssh_tunnel: str = ""

    # Division 2 — attack vector & parameter fuzzing
    graphql_introspection: bool = True
    enable_json_body: bool = True
    http_parameter_pollution: bool = True
    header_injection: bool = True
    host_header_injection: bool = True
    request_splitting: bool = True
    response_splitting: bool = True
    mime_type_confusion: bool = True
    null_byte_injection: bool = True
    polyglot_file_handling: bool = True
    magic_byte_detection: bool = True
    user_agent_rotation: bool = True
    rate_limit_enabled: bool = True
    rate_limit_rps: float = 20.0
    rate_limit_burst: int = 100


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
