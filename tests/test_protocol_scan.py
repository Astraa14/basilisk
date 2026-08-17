"""Integration tests for the ProtocolScanner orchestrator."""


from basilisk.dns import DnsResolver
from basilisk.http import RequestEngine
from basilisk.protocol_scan import ProtocolScanner
from tests import LocalServer


class TestProtocolScanner:
    def _scanner(self, server, path="/", **kwargs):
        engine = RequestEngine(timeout=2, follow_redirects=True)
        base = server.base_url
        defaults = {
            "engine": engine,
            "target_url": base + path,
            "enable_http2": False,
            "enable_http3": False,
            "dns_rebinding_check": False,
            "pipeline_check": True,
            "tcp_anomaly_check": False,
            "timeout": 2,
        }
        defaults.update(kwargs)
        return ProtocolScanner(**defaults)

    def test_run_produces_findings_and_summary(self, monkeypatch):
        monkeypatch.setattr(
            DnsResolver,
            "check_poisoning",
            lambda self, host: {"suspected": False, "evidence": []},
        )
        monkeypatch.setattr(
            DnsResolver,
            "check_rebinding",
            lambda self, host: {"rebinding": False, "evidence": []},
        )
        with LocalServer() as server:
            scanner = self._scanner(server)
            findings = scanner.run()
            assert scanner.summary["host"] == "127.0.0.1"
            assert "tls" in scanner.summary
            assert "alpn" in scanner.summary
            assert "pipelining" in scanner.summary
            assert findings  # at least pipelining-info or tls findings

    def test_make_finding_scores_cvss(self):
        scanner = ProtocolScanner(RequestEngine(timeout=1), "http://127.0.0.1/")
        finding = scanner._make_finding(
            "dns_rebinding", "DNS rebinding candidate", "High", "desc"
        )
        assert finding.attack_type == "dns_rebinding"
        assert finding.cvss_score > 0
        assert finding.cvss_vector.startswith("CVSS:3.1")

    def test_redirect_loop_finding(self, monkeypatch):
        monkeypatch.setattr(
            DnsResolver,
            "check_poisoning",
            lambda self, host: {"suspected": False, "evidence": []},
        )
        monkeypatch.setattr(
            DnsResolver,
            "check_rebinding",
            lambda self, host: {"rebinding": False, "evidence": []},
        )
        with LocalServer() as server:
            scanner = self._scanner(server, path="/redirect", pipeline_check=False)
            scanner.engine.max_redirects = 3
            findings = [f for f in scanner.run() if f.attack_type == "redirect_loop"]
            assert findings
            assert findings[0].severity == "Medium"

    def test_dns_rebinding_finding(self, monkeypatch):
        monkeypatch.setattr(
            DnsResolver,
            "check_poisoning",
            lambda self, host: {"suspected": False, "evidence": []},
        )
        monkeypatch.setattr(
            DnsResolver,
            "check_rebinding",
            lambda self, host: {
                "rebinding": True,
                "private_ips": ["127.0.0.1"],
                "evidence": ["private answer"],
            },
        )
        with LocalServer() as server:
            scanner = self._scanner(server, dns_rebinding_check=True)
            findings = [f for f in scanner.run() if f.attack_type == "dns_rebinding"]
            assert findings
            assert findings[0].severity == "High"