"""Tests for Basilisk heuristic judge."""

from basilisk.judge import HeuristicJudge


def make_response(status=200, body="", url="http://example.com", elapsed=0.1):
    return {"status_code": status, "body": body, "url": url, "elapsed_time": elapsed, "headers": {}}


class TestHeuristicJudgeSQLi:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_http_500_detected(self):
        resp = make_response(status=500, body="Internal Server Error")
        finding = self.judge.evaluate("sqli", "' OR 1=1 --", resp)
        assert finding is not None
        assert finding.severity == "High"
        assert "sqli" in finding.attack_type

    def test_db_error_signature_detected(self):
        resp = make_response(body="You have an error in your SQL syntax")
        finding = self.judge.evaluate("sqli", "test", resp)
        assert finding is not None
        assert "sql syntax" in finding.description.lower()

    def test_blind_time_based_detected(self):
        resp = make_response(body="", elapsed=5.5)
        finding = self.judge.evaluate("sqli", "1' SLEEP(5) --", resp)
        assert finding is not None
        assert "Timing" in finding.description

    def test_clean_response_no_finding(self):
        resp = make_response(body="Hello world")
        finding = self.judge.evaluate("sqli", "test", resp)
        assert finding is None


class TestHeuristicJudgeXSS:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_reflected_xss_detected(self):
        payload = "<script>alert(1)</script>"
        resp = make_response(body=f"Hello {payload} World")
        finding = self.judge.evaluate("xss", payload, resp)
        assert finding is not None
        assert finding.severity == "High"

    def test_partial_reflection_detected(self):
        payload = '" onmouseover="alert(1)"'
        stripped = payload.replace('"', '').replace("'", "")
        resp = make_response(body=stripped)
        finding = self.judge.evaluate("xss", payload, resp)
        assert finding is not None
        assert "partial" in finding.description.lower()

    def test_no_reflection(self):
        payload = "<script>alert(1)</script>"
        resp = make_response(body="No script here")
        finding = self.judge.evaluate("xss", payload, resp)
        assert finding is None


class TestHeuristicJudgeCMDI:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_uid_signature_detected(self):
        resp = make_response(body="uid=1000(www-data) gid=1000(www-data)")
        finding = self.judge.evaluate("cmdi", "; id", resp)
        assert finding is not None
        assert finding.severity == "Critical"
        assert finding.attack_type == "cmdi"

    def test_no_signature(self):
        resp = make_response(body="normal page content")
        finding = self.judge.evaluate("cmdi", "; id", resp)
        assert finding is None


class TestHeuristicJudgePathTraversal:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_passwd_content_detected(self):
        resp = make_response(body="root:x:0:0:root:/root:/bin/bash")
        finding = self.judge.evaluate("path_traversal", "../../../etc/passwd", resp)
        assert finding is not None
        assert finding.attack_type == "path_traversal"

    def test_no_leak(self):
        resp = make_response(body="Page not found")
        finding = self.judge.evaluate("path_traversal", "../../etc/passwd", resp)
        assert finding is None


class TestHeuristicJudgeSSTI:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_expression_evaluation(self):
        resp = make_response(body="Result: 49")
        finding = self.judge.evaluate("ssti", "{{7*7}}", resp)
        assert finding is not None
        assert finding.severity == "Critical"

    def test_no_evaluation(self):
        resp = make_response(body="Result: 7*7")
        finding = self.judge.evaluate("ssti", "{{7*7}}", resp)
        assert finding is None


class TestHeuristicJudgeSSRF:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_cloud_metadata_detected(self):
        resp = make_response(body="ami-id: ami-12345\niam: role-name")
        finding = self.judge.evaluate("ssrf", "http://169.254.169.254/latest/meta-data/", resp)
        assert finding is not None
        assert finding.severity == "Critical"

    def test_redirect_to_internal(self):
        resp = make_response(status=302, body="", url="http://example.com")
        resp["headers"] = {"Location": "http://127.0.0.1/admin"}
        finding = self.judge.evaluate("ssrf", "http://127.0.0.1:80", resp)
        assert finding is not None


class TestHeuristicJudgeNoSQLI:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_auth_bypass_detected(self):
        resp = make_response(body="Welcome to the admin dashboard")
        finding = self.judge.evaluate("nosqli", '{"$gt": ""}', resp)
        assert finding is not None
        assert finding.severity == "High"


class TestHeuristicJudgeLogin:
    def setup_method(self):
        self.judge = HeuristicJudge()

    def test_auth_bypass_indicator(self):
        resp = make_response(body="Welcome admin")
        finding = self.judge.evaluate("login", "' OR 1=1 --", resp)
        assert finding is not None

    def test_clean_response(self):
        resp = make_response(status=401, body="Invalid credentials")
        finding = self.judge.evaluate("login", "test", resp)
        assert finding is None
