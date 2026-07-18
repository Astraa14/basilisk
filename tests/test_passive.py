"""Tests for Basilisk passive analyzer."""

from basilisk.passive import PassiveAnalyzer


def make_response(headers=None, body="", url="http://example.com"):
    return {"headers": headers or {}, "body": body, "url": url}


class TestPassiveAnalyzer:
    def setup_method(self):
        self.analyzer = PassiveAnalyzer()

    def test_missing_security_headers_detected(self):
        resp = make_response(headers={"Server": "nginx/1.18.0"})
        findings = self.analyzer.analyze(resp)
        header_names = {f["vulnerability"] for f in findings}
        assert "Missing Security Header: X-Frame-Options" in header_names
        assert "Missing Security Header: Content-Security-Policy" in header_names

    def test_present_security_headers_not_reported(self):
        resp = make_response(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        })
        findings = self.analyzer.analyze(resp)
        header_names = {f["vulnerability"] for f in findings}
        assert "Missing Security Header: X-Frame-Options" not in header_names

    def test_server_version_info_disclosure(self):
        resp = make_response(headers={"Server": "Apache/2.4.41"})
        findings = self.analyzer.analyze(resp)
        disclosures = [f for f in findings if "Information Disclosure" in f["vulnerability"]]
        assert len(disclosures) > 0
        assert "Apache/2.4.41" in disclosures[0]["description"]

    def test_api_key_leak_detected(self):
        resp = make_response(body='api_key = "sk-abc123def456ghi789jkl012"')
        findings = self.analyzer.analyze(resp)
        leaks = [f for f in findings if "API Key" in f["vulnerability"]]
        assert len(leaks) > 0

    def test_email_leak_detected(self):
        resp = make_response(body="Contact: admin@example.com")
        findings = self.analyzer.analyze(resp)
        emails = [f for f in findings if "Email" in f["vulnerability"]]
        assert len(emails) > 0

    def test_internal_ip_leak_detected(self):
        resp = make_response(body="Server IP: 10.0.0.5")
        findings = self.analyzer.analyze(resp)
        ips = [f for f in findings if "IP Address" in f["vulnerability"]]
        assert len(ips) > 0

    def test_weak_csp_detected(self):
        resp = make_response(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        findings = self.analyzer.analyze(resp)
        weak_csp = [f for f in findings if "unsafe-inline" in f["vulnerability"]]
        assert len(weak_csp) > 0

    def test_jwt_leak_detected(self):
        resp = make_response(body="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP")
        findings = self.analyzer.analyze(resp)
        jwt = [f for f in findings if "JWT" in f["vulnerability"]]
        assert len(jwt) > 0

    def test_aws_key_leak_detected(self):
        resp = make_response(body="AKIAIOSFODNN7EXAMPLE")
        findings = self.analyzer.analyze(resp)
        aws = [f for f in findings if "AWS" in f["vulnerability"]]
        assert len(aws) > 0

    def test_none_response_returns_empty(self):
        findings = self.analyzer.analyze(None)
        assert findings == []

    def test_weak_hsts_detected(self):
        resp = make_response(headers={"Strict-Transport-Security": "max-age=3600"})
        findings = self.analyzer.analyze(resp)
        hsts = [f for f in findings if "Weak HSTS" in f["vulnerability"]]
        assert len(hsts) > 0

    def test_missing_content_type(self):
        resp = make_response(headers={})
        findings = self.analyzer.analyze(resp)
        ct = [f for f in findings if "Missing Content-Type" in f["vulnerability"]]
        assert len(ct) > 0
