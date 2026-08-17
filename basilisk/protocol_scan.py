"""Protocol & transport layer scan — runs transport probes against a target
and converts results into Findings:

    DNS (poisoning / rebinding), TLS certificates, ALPN negotiation,
    HTTP/2 & HTTP/3, server push, pipelining, TCP stability, redirect loops.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from urllib.parse import urlparse

from basilisk.dns import DnsResolver
from basilisk.http import RequestEngine
from basilisk.models import Finding
from basilisk.pipelining import PipelineProbe
from basilisk.scoring import score_finding
from basilisk.tcp import TcpProber, TcpTracker
from basilisk.transport import (
    AlpnProbe,
    Http2Client,
    Http3Client,
    PushProbe,
    TlsProbe,
)

logger = logging.getLogger(__name__)

ProgressCb = Callable[[str], None]

WEAK_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 30


class ProtocolScanner:
    """Runs Division-1 transport checks against one target origin."""

    def __init__(
        self,
        engine: RequestEngine,
        target_url: str,
        verify_tls: bool = True,
        enable_http2: bool = True,
        enable_http3: bool = False,
        dns_rebinding_check: bool = True,
        pipeline_check: bool = True,
        tcp_anomaly_check: bool = True,
        timeout: float = 5.0,
    ):
        self.engine = engine
        self.target_url = target_url.rstrip("/")
        parsed = urlparse(self.target_url)
        self.host = parsed.hostname or ""
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.verify_tls = verify_tls
        self.enable_http2 = enable_http2
        self.enable_http3 = enable_http3
        self.dns_rebinding_check = dns_rebinding_check
        self.pipeline_check = pipeline_check
        self.tcp_anomaly_check = tcp_anomaly_check
        self.timeout = timeout
        self.tracker = TcpTracker()
        self.summary: dict = {"host": self.host, "port": self.port}

    def run(self, on_progress: ProgressCb | None = None) -> list[Finding]:
        findings: list[Finding] = []

        def note(msg: str) -> None:
            if on_progress:
                on_progress(msg)

        if self.host:
            note(f"Protocol: DNS checks on {self.host}")
            findings.extend(self._dns_checks())

        note(f"Protocol: TLS/ALPN inspection of {self.host}:{self.port}")
        findings.extend(self._tls_checks())
        findings.extend(self._alpn_checks())

        if self.enable_http2:
            note(f"Protocol: HTTP/2 request on {self.target_url}")
            findings.extend(self._http2_checks())

        if self.enable_http3:
            note(f"Protocol: HTTP/3 request on {self.target_url}")
            findings.extend(self._http3_checks())

        if self.pipeline_check and not self.enable_http3:
            note("Protocol: HTTP/1.1 pipelining probe")
            findings.extend(self._pipeline_checks())

        if self.tcp_anomaly_check:
            note(f"Protocol: TCP stability probe on {self.host}:{self.port}")
            findings.extend(self._tcp_checks())

        findings.extend(self._redirect_checks())

        if findings:
            logger.info(
                "Protocol scan produced %d finding(s) for %s",
                len(findings),
                self.target_url,
            )
        return findings

    def _make_finding(
        self,
        attack_type: str,
        vulnerability: str,
        severity: str,
        description: str,
        target: str = "",
    ) -> Finding:
        cvss, vector = score_finding(attack_type)
        return Finding(
            vulnerability=vulnerability,
            severity=severity,
            description=description,
            target=target or self.target_url,
            attack_type=attack_type,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="",
        )

    def _dns_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.host:
            return findings
        resolver = DnsResolver(timeout=min(self.timeout, 2.0))
        try:
            poisoning = resolver.check_poisoning(self.host)
        except Exception as exc:
            logger.debug("DNS poisoning check failed for %s: %s", self.host, exc)
            poisoning = {"suspected": False, "evidence": []}
        self.summary["dns_poisoning"] = poisoning
        if poisoning.get("suspected"):
            evidence = "; ".join(poisoning.get("evidence", []))[:500]
            findings.append(
                self._make_finding(
                    "dns_poisoning",
                    "DNS poisoning suspected",
                    "High",
                    "Target hostname resolves inconsistently across independent "
                    f"resolvers: {evidence}",
                )
            )

        if self.dns_rebinding_check:
            try:
                rebinding = resolver.check_rebinding(self.host)
            except Exception as exc:
                logger.debug("DNS rebinding check failed for %s: %s", self.host, exc)
                rebinding = {"rebinding": False, "evidence": []}
            self.summary["dns_rebinding"] = rebinding
            if rebinding.get("rebinding"):
                private = ", ".join(rebinding.get("private_ips", []))
                details = "; ".join(rebinding.get("evidence", []))[:500]
                findings.append(
                    self._make_finding(
                        "dns_rebinding",
                        "DNS rebinding candidate",
                        "High",
                        f"Hostname resolves to private/reserved addresses "
                        f"({private}): {details}",
                    )
                )
        return findings

    def _tls_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        probe = TlsProbe(timeout=self.timeout)
        info = probe.probe(self.host, self.port)
        self.summary["tls"] = {
            "verified": info.verified,
            "protocol": info.protocol,
            "cipher": info.cipher,
            "subject": info.subject,
            "issuer": info.issuer,
            "expired": info.expired,
            "days_left": round(info.days_left, 1),
            "alpn": info.alpn,
        }
        if info.expired:
            age = f"{abs(info.days_left):.0f} days ago" if info.days_left else ""
            findings.append(
                self._make_finding(
                    "tls",
                    "Expired TLS certificate",
                    "High",
                    f"Certificate for {self.host} expired {age} "
                    f"(issuer: {info.issuer}; subject: {info.subject})",
                )
            )
        if not info.verified:
            findings.append(
                self._make_finding(
                    "tls",
                    "TLS certificate validation failure",
                    "Medium",
                    "Certificate chain for "
                    f"{self.host} did not validate: "
                    f"{info.verification_error or 'unknown error'}"
                    + ("; certificate appears self-signed." if info.self_signed else ""),
                )
            )
        elif info.days_left < EXPIRY_WARNING_DAYS and not info.expired:
            findings.append(
                self._make_finding(
                    "tls",
                    "TLS certificate expiring soon",
                    "Low",
                    f"Certificate for {self.host} expires in "
                    f"{int(info.days_left)} days (issuer: {info.issuer})",
                )
            )
        if info.protocol in WEAK_TLS_VERSIONS:
            findings.append(
                self._make_finding(
                    "tls",
                    "Weak TLS protocol version",
                    "High",
                    f"Server negotiates {info.protocol}, which is deprecated; "
                    "modern clients require TLSv1.2+.",
                )
            )
        return findings

    def _alpn_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        probe = AlpnProbe(timeout=self.timeout)
        info = probe.probe(self.host, self.port)
        self.summary["alpn"] = {
            "supports_h2": info.supports_h2,
            "negotiated_with_h2_offered": info.negotiated_with_h2,
            "negotiated_with_http11_only": info.negotiated_with_http11,
        }
        if not info.supports_h2 and self.enable_http2:
            findings.append(
                self._make_finding(
                    "alpn",
                    "HTTP/2 not supported",
                    "Info",
                    f"Server negotiated {info.negotiated_with_http11 or 'no ALPN'} "
                    "when h2 was offered — h2 stream-multiplexing features "
                    "unavailable to modern clients.",
                )
            )
        if info.supports_h2:
            findings.append(
                self._make_finding(
                    "alpn",
                    "ALPN: HTTP/2 negotiated",
                    "Info",
                    "Server supports HTTP/2 over ALPN. Ensure h2 request "
                    "smuggling mitigations (RFC 9113) are applied.",
                )
            )
        return findings

    def _http2_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        client = Http2Client()
        result = client.request("GET", self.target_url, timeout=self.timeout)
        self.summary["http2"] = {
            "ok": result.ok,
            "protocol": result.protocol,
            "status_code": result.status_code,
            "error": result.error,
        }
        if result.ok and result.protocol.startswith("h2"):
            push = PushProbe(timeout=self.timeout).probe(self.host, self.port)
            self.summary["http2_push"] = {
                "enabled": push.enabled,
                "push_frames": push.push_frames,
                "server_enable_push": push.server_enable_push,
                "evidence": push.evidence,
            }
            if push.enabled:
                findings.append(
                    self._make_finding(
                        "http2_push",
                        "HTTP/2 Server Push enabled",
                        "Medium",
                        "Server advertises HTTP/2 server push ("
                        + "; ".join(push.evidence[:3])
                        + "). Push is deprecated in browsers; aggressive "
                        "preload/push usage can enable cache poisoning and "
                        "resource-waste attacks.",
                    )
                )
        elif result.ok:
            findings.append(
                self._make_finding(
                    "alpn",
                    "HTTP/1.1 response to h2 client",
                    "Info",
                    f"h2-capable client received HTTP/{result.protocol} — "
                    "server downgraded the connection.",
                )
            )
        return findings

    def _http3_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        client = Http3Client()
        if not client.available:
            self.summary["http3"] = {"ok": False, "error": "http3 transport unavailable"}
            return findings
        result = client.request("GET", self.target_url, timeout=self.timeout)
        self.summary["http3"] = {
            "ok": result.ok,
            "protocol": result.protocol,
            "status_code": result.status_code,
            "error": result.error,
        }
        if result.ok:
            findings.append(
                self._make_finding(
                    "alpn",
                    "HTTP/3 (QUIC) reachable",
                    "Info",
                    f"HTTP/3 request completed over {result.protocol} "
                    f"(status {result.status_code}) — verify QUIC-specific "
                    "exposure and Alt-Svc consistency.",
                )
            )
        return findings

    def _pipeline_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        probe = PipelineProbe(timeout=self.timeout, tracker=self.tracker)
        result = probe.probe(self.host, self.port, tls=(self.port == 443))
        self.summary["pipelining"] = {
            "supported": result.supported,
            "statuses": result.statuses,
            "evidence": result.evidence,
        }
        if result.supported:
            severity = "Info" if result.ordered else "Medium"
            findings.append(
                self._make_finding(
                    "pipelining",
                    "HTTP/1.1 pipelining accepted",
                    severity,
                    "Server answered multiple back-to-back requests on one "
                    "connection — classic request-smuggling surface. Cross-check "
                    "with CL/TE desync tests (basilisk.smuggling). Evidence: "
                    + "; ".join(result.evidence[:3]),
                )
            )
        return findings

    def _tcp_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        prober = TcpProber(tracker=self.tracker, timeout=min(self.timeout, 3.0))
        report = prober.probe(self.host, self.port, attempts=5)
        self.summary["tcp"] = report
        for anomaly in report.get("anomalies", []):
            findings.append(
                self._make_finding(
                    "tcp_anomaly",
                    anomaly["label"],
                    anomaly["severity"],
                    anomaly["detail"] + f" (endpoint {self.host}:{self.port})",
                )
            )
        return findings

    def _redirect_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        try:
            response = self.engine.send("GET", self.target_url, follow_redirects=True)
        except Exception as exc:
            logger.debug("Redirect probe failed for %s: %s", self.target_url, exc)
            return findings
        if not response:
            return findings
        loop = response.get("redirect_loop")
        chain = response.get("redirect_chain", [])
        self.summary["redirects"] = {
            "loop": bool(loop),
            "chain": chain[:12],
            "final_status": response.get("status_code"),
        }
        if loop:
            findings.append(
                self._make_finding(
                    "redirect_loop",
                    "Redirect loop detected",
                    "Medium",
                    f"Following redirects from {self.target_url} cycles through "
                    f"{len(chain)} URL(s): {' -> '.join(chain[:6])}...",
                )
            )
        elif len(chain) >= self.engine.max_redirects:
            findings.append(
                self._make_finding(
                    "redirect_loop",
                    "Excessive redirect chain",
                    "Low",
                    f"Redirect following hit the {self.engine.max_redirects}-hop "
                    f"limit from {self.target_url}; a loop or very long chain is "
                    "possible: " + " -> ".join(chain[:6]) + "...",
                )
            )
        return findings
