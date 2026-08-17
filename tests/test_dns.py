"""Tests for DNS resolution, caching, poisoning and rebinding detection."""

import ipaddress
import struct

from basilisk.dns import (
    DnsCache,
    DnsResolver,
    build_query,
    decode_name,
    encode_name,
    is_private_ip,
    parse_response,
)


class TestEncodeDecode:
    def test_encode_name(self):
        assert encode_name("example.com") == b"\x07example\x03com\x00"
        assert encode_name("localhost") == b"\x09localhost\x00"

    def test_decode_name_roundtrip(self):
        encoded = encode_name("www.example.com")
        name, offset = decode_name(encoded + b"\x00\x00", 0)
        assert name == "www.example.com"
        assert offset == len(encoded)

    def test_decode_compression_pointer(self):
        # "example.com" followed by a pointer back to its own start (0xC0 0x00)
        encoded = b"\x07example\x03com\x00\xc0\x00"
        name, offset = decode_name(encoded + b"ZZ", 13)
        assert name == "example.com"
        assert offset == 15


class TestParseResponse:
    def _make_a_response(self, query: bytes, query_id: int, ip: str) -> bytes:
        # locate the end of the QNAME without hitting the header query-id bytes
        pos = 12
        while pos < len(query) and query[pos] != 0:
            pos += query[pos] + 1
        question = query[12 : pos + 1 + 4]
        ip_bytes = ipaddress.ip_address(ip).packed
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
        header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
        return header + question + answer

    def test_parse_a_record(self):
        query, query_id = build_query("example.com", 1, query_id=42)
        response = self._make_a_response(query, query_id, "93.184.216.34")
        records, rcode, truncated = parse_response(response, query_id)
        assert rcode == 0
        assert not truncated
        assert records[0]["ip"] == "93.184.216.34"
        assert records[0]["ttl"] == 300

    def test_wrong_query_id_rejected(self):
        query, query_id = build_query("example.com", 1, query_id=42)
        response = self._make_a_response(query, query_id, "93.184.216.34")
        records, rcode, _ = parse_response(response, 99)
        assert records == []
        assert rcode == -1


class TestPrivateIp:
    def test_private_ranges(self):
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("10.0.0.5")
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("::1")
        assert is_private_ip("fe80::1")
        assert is_private_ip("169.254.1.1")
        assert is_private_ip("100.64.0.1")

    def test_public_ranges(self):
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("93.184.216.34")
        assert not is_private_ip("2606:4700::1111")

    def test_garbage(self):
        assert not is_private_ip("not-an-ip")
        assert not is_private_ip("")


class TestDnsCache:
    def test_cache_hit_and_ttl(self, monkeypatch):
        cache = DnsCache()
        records = [{"ip": "1.2.3.4", "ttl": 100, "type": "A"}]
        cache.set(("example.com", "A", "8.8.8.8"), records)
        assert cache.get(("example.com", "A", "8.8.8.8")) == records

    def test_ttl_clamped(self):
        cache = DnsCache()
        cache.set(("x.com", "A", "8.8.8.8"), [{"ip": "1.1.1.1", "ttl": 0, "type": "A"}])
        entry = cache.get(("x.com", "A", "8.8.8.8"))
        assert entry is not None

    def test_miss(self):
        cache = DnsCache()
        assert cache.get(("nope.com", "A", "8.8.8.8")) is None


class TestRebindingDetection:
    def test_private_answer_flags_rebinding(self, monkeypatch):
        resolver = DnsResolver(timeout=0.5)
        monkeypatch.setattr(
            resolver,
            "udp_resolve",
            lambda host, qtype="A", server="8.8.8.8", timeout=None: (
                [{"ip": "127.0.0.1", "ttl": 0, "type": "A"}]
                if qtype == "A"
                else [{"ip": "::1", "ttl": 0, "type": "AAAA"}]
            ),
        )
        result = resolver.check_rebinding("evil.example.com", queries=1, delay=0)
        assert result["rebinding"] is True
        assert "127.0.0.1" in result["private_ips"]

    def test_public_answer_clean(self, monkeypatch):
        resolver = DnsResolver(timeout=0.5)
        monkeypatch.setattr(
            resolver,
            "udp_resolve",
            lambda host, qtype="A", server="8.8.8.8", timeout=None: (
                [{"ip": "93.184.216.34", "ttl": 0, "type": "A"}]
                if qtype == "A"
                else []
            ),
        )
        result = resolver.check_rebinding("example.com", queries=1, delay=0)
        assert result["rebinding"] is False

    def test_ip_literal_skipped(self):
        resolver = DnsResolver(timeout=0.5)
        result = resolver.check_rebinding("127.0.0.1")
        assert result["rebinding"] is False


class TestPoisoningDetection:
    def test_disagreement_detected(self, monkeypatch):
        resolver = DnsResolver(timeout=0.5)
        system_ip = "1.1.1.1"
        public_ip = "93.184.216.34"

        def fake_udp(host, qtype="A", server="8.8.8.8", timeout=None):
            ip = public_ip if server != "8.8.8.8" else system_ip
            return [{"ip": ip, "ttl": 0, "type": "A"}]

        monkeypatch.setattr(resolver, "udp_resolve", fake_udp)
        result = resolver.check_poisoning("example.com")
        assert result["suspected"] is True
        assert len(result["disagreements"]) >= 1

    def test_consistent_answers_clean(self, monkeypatch):
        resolver = DnsResolver(timeout=0.5)

        def fake_udp(host, qtype="A", server="8.8.8.8", timeout=None):
            return [{"ip": "93.184.216.34", "ttl": 0, "type": "A"}]

        monkeypatch.setattr(resolver, "udp_resolve", fake_udp)
        monkeypatch.setattr(resolver, "system_resolve", lambda host: ["93.184.216.34"])
        result = resolver.check_poisoning("example.com")
        assert result["suspected"] is False