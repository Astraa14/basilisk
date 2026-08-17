"""Tests for the HTTP/1.1 pipelining probe and transport probes."""

from basilisk.pipelining import PipelineProbe
from basilisk.transport import AlpnProbe, Http2Client, PushProbe, TlsProbe
from tests import LocalServer


class TestPipelineProbe:
    def test_pipelining_detected(self):
        with LocalServer() as server:
            host, port = server.base_url.replace("http://", "").split(":")
            probe = PipelineProbe(timeout=2)
            result = probe.probe(host, int(port), tls=False)
            assert result.supported is True
            assert len(result.statuses) >= 2
            assert all(s == 200 for s in result.statuses[:2])
            assert result.error == ""

    def test_pipeline_request_count(self):
        with LocalServer() as server:
            host, port = server.base_url.replace("http://", "").split(":")
            probe = PipelineProbe(timeout=2)
            probe.probe(host, int(port), tls=False)
            assert len(server.requests) >= 2

    def test_refused_connection_error(self):
        probe = PipelineProbe(timeout=1)
        result = probe.probe("127.0.0.1", 1, tls=False)
        assert result.supported is False
        assert result.error != ""


class TestTlsProbe:
    def test_plain_http_server_fails_verification(self):
        with LocalServer() as server:
            host, port = server.base_url.replace("http://", "").split(":")
            info = TlsProbe(timeout=2).probe(host, int(port))
            assert info.verified is False
            assert info.verification_error != ""


class TestAlpnProbe:
    def test_plain_http_server_no_alpn(self):
        with LocalServer() as server:
            host, port = server.base_url.replace("http://", "").split(":")
            info = AlpnProbe(timeout=2).probe(host, int(port))
            assert info.supports_h2 is False
            assert info.negotiated_with_h2 == ""


class TestPushProbe:
    def test_falls_back_without_h2(self):
        with LocalServer() as server:
            host, port = server.base_url.replace("http://", "").split(":")
            result = PushProbe(timeout=2).probe(host, int(port), scheme="http")
            assert result.checked is True
            assert result.push_frames == 0


class TestHttp2Client:
    def test_degrades_without_httpx(self, monkeypatch):
        monkeypatch.setattr("basilisk.transport.HAS_HTTPX", False)
        client = Http2Client()
        result = client.request("GET", "https://example.com/")
        assert result.ok is False
        assert result.error != ""