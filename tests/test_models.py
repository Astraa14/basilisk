"""Tests for Basilisk data models."""

from basilisk.models import Finding, ScanReport, AttackType


class TestFinding:
    def test_minimal_creation(self):
        f = Finding(vulnerability="XSS", severity="High", description="test", target="http://example.com")
        assert f.vulnerability == "XSS"
        assert f.severity == "High"
        assert f.attack_type == ""
        assert f.payload == ""

    def test_full_creation(self):
        f = Finding(
            vulnerability="SQLi", severity="Critical", description="test",
            target="http://example.com", attack_type="sqli", payload="' OR 1=1 --"
        )
        assert f.attack_type == "sqli"
        assert f.payload == "' OR 1=1 --"

    def test_to_dict_excludes_empty(self):
        f = Finding(vulnerability="XSS", severity="Low", description="x", target="t")
        d = f.to_dict()
        assert "attack_type" not in d
        assert "payload" not in d


class TestScanReport:
    def test_empty_report(self):
        r = ScanReport(target="http://example.com")
        assert r.target == "http://example.com"
        assert r.findings == []
        assert r.vulnerable is False

    def test_vulnerable_flag(self):
        r = ScanReport(target="t", vulnerable=True)
        assert r.vulnerable is True
        assert r.to_dict()["vulnerable"] is True

    def test_to_dict_converts_findings(self):
        f = Finding(vulnerability="XSS", severity="High", description="xss", target="t")
        r = ScanReport(target="t", findings=[f])
        d = r.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["vulnerability"] == "XSS"


class TestAttackType:
    def test_all_types_present(self):
        types = {t.value for t in AttackType}
        assert "sqli" in types
        assert "xss" in types
        assert "cmdi" in types
        assert "path_traversal" in types
        assert "ssti" in types
        assert "ssrf" in types
        assert "open_redirect" in types
        assert "lfi" in types
        assert "nosqli" in types
