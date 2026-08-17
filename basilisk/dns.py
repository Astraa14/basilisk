"""DNS resolution and abuse detection — TTL cache, minimal UDP resolver,
cross-source poisoning detection, and DNS rebinding detection."""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import struct
import threading
import time

logger = logging.getLogger(__name__)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),
]

PUBLIC_DNS_SERVERS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")

QTYPE_MAP = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16}

CACHE_TTL_MIN = 5
CACHE_TTL_MAX = 3600


def is_private_ip(ip: str) -> bool:
    """True when an IP literal falls in private/reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        encoded = label.encode("idna")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        labels.append(
            data[offset + 1 : offset + 1 + length].decode("latin-1")
        )
        offset += 1 + length
    return ".".join(labels), end_offset


def build_query(name: str, qtype: int, query_id: int | None = None) -> tuple[bytes, int]:
    query_id = query_id or random.randint(0, 0xFFFF)
    flags = 0x0100  # RD
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + question, query_id


def parse_response(data: bytes, query_id: int) -> tuple[list[dict], int, bool]:
    """Parse a DNS response into (records, rcode, truncated)."""
    if len(data) < 12:
        return [], -1, False
    resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if resp_id != query_id:
        return [], -1, False
    rcode = flags & 0x0F
    truncated = bool(flags & 0x0200)
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4  # qtype + qclass
    records: list[dict] = []
    for _ in range(ancount):
        _, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_start = offset
        if rtype == 1 and rdlength == 4:  # A
            ip = socket.inet_ntop(socket.AF_INET, data[offset : offset + 4])
            records.append({"ip": ip, "ttl": ttl, "type": "A"})
        elif rtype == 28 and rdlength == 16:  # AAAA
            ip = socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16])
            records.append({"ip": ip, "ttl": ttl, "type": "AAAA"})
        elif rtype == 5:  # CNAME
            cname, _ = decode_name(data, offset)
            records.append({"cname": cname, "ttl": ttl, "type": "CNAME"})
        offset = rdata_start + rdlength
    return records, rcode, truncated


class DnsCache:
    """Thread-safe TTL-bounded DNS answer cache keyed by (host, qtype, server)."""

    def __init__(self):
        self._store: dict[tuple, tuple] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple) -> list[dict] | None:
        with self._lock:
            entry = self._store.get(tuple(key))
            if entry is None:
                return None
            records, expires = entry
            if time.monotonic() > expires:
                self._store.pop(tuple(key), None)
                return None
            return list(records)

    def set(self, key: tuple, records: list[dict]) -> None:
        ttl_values = [r.get("ttl") for r in records if r.get("ttl") is not None]
        ttl = min(ttl_values) if ttl_values else CACHE_TTL_MIN
        ttl = max(CACHE_TTL_MIN, min(CACHE_TTL_MAX, int(ttl)))
        with self._lock:
            self._store[tuple(key)] = (list(records), time.monotonic() + ttl)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class DnsResolver:
    """Multi-source DNS resolution with caching and abuse checks."""

    def __init__(self, timeout: float = 2.0, use_cache: bool = True):
        self.timeout = timeout
        self.cache = DnsCache() if use_cache else None

    # ── resolution ────────────────────────────────────────────────────────

    def system_resolve(self, host: str, timeout: float | None = None) -> list[str]:
        """Resolve via the operating-system resolver (getaddrinfo)."""
        try:
            info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        ips: list[str] = []
        for family, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips

    def udp_resolve(
        self,
        host: str,
        qtype: str = "A",
        server: str = "8.8.8.8",
        timeout: float | None = None,
    ) -> list[dict] | None:
        """Query a specific DNS server over UDP. Returns parsed records or None."""
        key = (host, qtype, server)
        if self.cache:
            cached = self.cache.get(key)
            if cached is not None:
                return cached
        qtype_num = QTYPE_MAP.get(qtype.upper(), 1)
        packet, query_id = build_query(host, qtype_num)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout or self.timeout)
            try:
                sock.sendto(packet, (server, 53))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
        except OSError as exc:
            logger.debug("UDP DNS query to %s for %s failed: %s", server, host, exc)
            return None
        records, rcode, _truncated = parse_response(data, query_id)
        if rcode != 0 or not records:
            return None
        if self.cache:
            self.cache.set(key, records)
        return records

    def resolve_all(
        self,
        host: str,
        servers: tuple[str, ...] = PUBLIC_DNS_SERVERS,
        include_system: bool = True,
    ) -> dict[str, list[str]]:
        """Resolve a host from multiple independent sources."""
        sources: dict[str, list[str]] = {}
        if include_system:
            sources["system"] = self.system_resolve(host)
        for server in servers:
            records = self.udp_resolve(host, "A", server)
            ips = [r["ip"] for r in records if r.get("ip")] if records else []
            records6 = self.udp_resolve(host, "AAAA", server)
            ips += [r["ip"] for r in records6 if r.get("ip")] if records6 else []
            if ips:
                sources[server] = list(dict.fromkeys(ips))
        return sources

    # ── poisoning detection ───────────────────────────────────────────────

    def _split_families(self, ips: list[str]) -> dict[str, set[str]]:
        families: dict[str, set[str]] = {"4": set(), "6": set()}
        for ip in ips:
            try:
                family = ipaddress.ip_address(ip).version
                families[str(family)].add(ip)
            except ValueError:
                continue
        return families

    def check_poisoning(self, host: str) -> dict:
        """Compare answers across resolvers and over time.

        Returns {suspected, evidence: [str], answers, disagreements}.
        Comparisons are per-IP-family so a resolver that simply lacks AAAA
        answers does not count as disagreement. A mismatch within the same
        family between independent resolvers may indicate cache poisoning
        OR split-horizon DNS.
        """
        sources = self.resolve_all(host)
        evidence: list[str] = []
        disagreements: list[str] = []

        # Group by family; for each family compare answer sets across sources
        # that actually answered that family.
        by_family: dict[str, dict[str, set[str]]] = {"4": {}, "6": {}}
        for source, ips in sources.items():
            fams = self._split_families(ips)
            for family in ("4", "6"):
                if fams[family]:
                    by_family[family][source] = fams[family]

        for family in ("4", "6"):
            members = by_family[family]
            if len(members) < 2:
                continue
            distinct = {frozenset(v) for v in members.values()}
            if len(distinct) > 1:
                for source, ip_set in members.items():
                    others = [
                        s
                        for s, other_set in members.items()
                        if s != source and other_set != ip_set
                    ]
                    if others:
                        disagreements.append(
                            f"IPv{family} {','.join([source] + others)} disagree: "
                            f"{sorted(ip_set)} vs "
                            f"{sorted(next(v for s, v in members.items() if s != source))}"
                        )
                evidence.append(
                    f"IPv{family} answers differ across independent resolvers"
                )

        # Stability: same public resolver queried back-to-back should agree.
        for server in PUBLIC_DNS_SERVERS:
            first = self.udp_resolve(host, "A", server)
            second = self.udp_resolve(host, "A", server)
            if first and second:
                a = {r["ip"] for r in first}
                b = {r["ip"] for r in second}
                if a != b:
                    evidence.append(
                        f"resolver {server} returned unstable answers across "
                        f"consecutive queries ({sorted(a)} vs {sorted(b)})"
                    )

        return {
            "suspected": bool(disagreements or evidence),
            "evidence": evidence,
            "disagreements": disagreements,
            "answers": {k: sorted(v) for k, v in sources.items()},
            "host": host,
        }

    # ── rebinding detection ───────────────────────────────────────────────

    def check_rebinding(self, host: str, queries: int = 3, delay: float = 0.15) -> dict:
        """Probe for DNS pinning/rebinding-resistant answers.

        A public hostname that resolves to private/reserved ranges (or
        flips to one between queries) is a DNS rebinding candidate.
        Returns {rebinding: bool, private_ips: [str], evidence: [str]}.
        """
        if is_private_ip(host):
            return {"rebinding": False, "private_ips": [], "evidence": []}
        try:
            ipaddress.ip_address(host)
            return {"rebinding": False, "private_ips": [], "evidence": []}
        except ValueError:
            pass

        all_ips: list[str] = []
        private: list[str] = []
        evidence: list[str] = []

        for attempt in range(queries):
            if delay and attempt:
                time.sleep(delay)
            for qtype in ("A", "AAAA"):
                for server in PUBLIC_DNS_SERVERS[:2]:
                    records = self.udp_resolve(host, qtype, server)
                    if not records:
                        continue
                    ips = [r["ip"] for r in records if r.get("ip")]
                    for ip in ips:
                        if ip not in all_ips:
                            all_ips.append(ip)
                        if is_private_ip(ip) and ip not in private:
                            private.append(ip)
                            evidence.append(
                                f"query {attempt + 1} via {server} resolved {host} "
                                f"to private/reserved address {ip}"
                            )

        if private:
            evidence.append(
                f"hostname {host} answered with non-public addresses "
                f"({', '.join(sorted(private))}) — DNS rebinding / SSRF candidate"
            )
        return {
            "rebinding": bool(private),
            "private_ips": sorted(private),
            "evidence": evidence,
            "all_ips": sorted(all_ips),
            "host": host,
        }