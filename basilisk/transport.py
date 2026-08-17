"""Protocol & TLS layer — certificate validation, ALPN negotiation,
HTTP/2 and HTTP/3 clients, and HTTP/2 Server Push detection.

All optional dependencies (h2, httpx[http2], httpx[http3]) degrade
gracefully so the scanner still works without them.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import h2.config
    import h2.connection
    import h2.events

    HAS_H2 = True
except ImportError:
    HAS_H2 = False

try:
    import quic_transport  # type: ignore

    HAS_HTTP3 = True
except ImportError:
    HAS_HTTP3 = False


@dataclass
class TlsInfo:
    host: str
    port: int
    verified: bool = False
    verification_error: str = ""
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    days_left: float = 0.0
    self_signed: bool = False
    protocol: str = ""
    cipher: str = ""
    alpn: str = ""


@dataclass
class AlpnInfo:
    host: str
    negotiated_with_h2: str = ""
    negotiated_with_http11: str = ""
    supports_h2: bool = False
    forces_http11: bool = False
    observations: list[str] = field(default_factory=list)


@dataclass
class PushInfo:
    checked: bool = False
    push_frames: int = 0
    server_enable_push: int | None = None
    preload_links: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return self.push_frames > 0 or self.server_enable_push not in (None, 0)


@dataclass
class ProtocolResult:
    ok: bool = False
    protocol: str = ""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    latency_ms: float = 0.0
    error: str = ""


def _cert_attr(cert: dict, key: str) -> str:
    """Extract a single-valued attribute (e.g. commonName) from an X509 subject/issuer."""
    for entry in cert.get(key, []):
        for name, value in entry:
            if name == "commonName":
                return str(value)
    return ""


class TlsProbe:
    """TLS handshake inspection with graceful handling of bad certificates."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe(self, host: str, port: int = 443) -> TlsInfo:
        info = TlsInfo(host=host, port=port)
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        try:
            raw = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as exc:
            info.verification_error = f"connect failed: {exc}"
            return info
        try:
            try:
                tls = context.wrap_socket(raw, server_hostname=host)
                info.verified = True
            except ssl.SSLCertVerificationError as exc:
                info.verified = False
                info.verification_error = exc.verify_message or str(exc)
                loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                loose.check_hostname = False
                loose.verify_mode = ssl.CERT_NONE
                try:
                    loose.set_alpn_protocols(["h2", "http/1.1"])
                except Exception:
                    pass
                tls = loose.wrap_socket(raw, server_hostname=host)
            except ssl.SSLError as exc:
                info.verification_error = f"TLS handshake error: {exc}"
                return info

            cert = tls.getpeercert()
            if cert:
                info.subject = _cert_attr(cert, "subject")
                info.issuer = _cert_attr(cert, "issuer")
                san_raw = cert.get("subjectAltName", [])
                info.san = [value for _, value in san_raw]
                info.not_before = str(cert.get("notBefore", ""))
                info.not_after = str(cert.get("notAfter", ""))
                if cert.get("notAfter"):
                    try:
                        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        now = datetime.now(timezone.utc)
                        info.expired = expiry < now
                        info.days_left = (expiry - now).total_seconds() / 86400.0
                    except ValueError:
                        pass
                info.self_signed = bool(info.subject) and info.subject == info.issuer
            info.protocol = tls.version() or ""
            cipher = tls.cipher()
            info.cipher = f"{cipher[0]} ({cipher[1]})" if cipher else ""
            info.alpn = tls.selected_alpn_protocol() or ""
            try:
                tls.unwrap()
            except Exception:
                pass
        except OSError as exc:
            info.verification_error = f"TLS read failed: {exc}"
        finally:
            try:
                raw.close()
            except Exception:
                pass
        return info


class AlpnProbe:
    """Verify which protocols a server negotiates when ALPN is offered."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe(self, host: str, port: int = 443) -> AlpnInfo:
        info = AlpnInfo(host=host)
        offers = (("h2", "http/1.1"), ("http/1.1",))

        for offered in offers:
            context = ssl.create_default_context()
            context.set_alpn_protocols(list(offered))
            try:
                raw = socket.create_connection((host, port), timeout=self.timeout)
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    selected = tls.selected_alpn_protocol() or ""
            except Exception as exc:
                logger.debug("ALPN probe (%s) failed for %s: %s", offered, host, exc)
                break
            if "h2" in offered:
                info.negotiated_with_h2 = selected
                info.supports_h2 = selected == "h2"
            else:
                info.negotiated_with_http11 = selected
                if info.supports_h2 and selected != "h2":
                    info.observations.append(
                        "server downgraded negotiation when h2 was removed from ALPN"
                    )
                if not info.supports_h2 and selected == "http/1.1":
                    info.forces_http11 = True
                    info.observations.append("server only negotiates http/1.1")
        return info


class PushProbe:
    """Detect HTTP/2 Server Push via PUSH_PROMISE frames on an active h2 stream.

    Falls back to caching headers (Link: rel=preload + Alt-Svc) when the
    h2 library is unavailable.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe(self, host: str, port: int = 443, scheme: str = "https") -> PushInfo:
        result = PushInfo(checked=True)
        if not HAS_H2:
            result.evidence.append("h2 library unavailable — header heuristic only")
            return self._header_fallback(host, port, scheme, result)

        try:
            config = h2.config.H2Configuration(client_side=True)
            connection = h2.connection.H2Connection(config=config)
            connection.initiate_connection()

            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2"])
            raw = socket.create_connection((host, port), timeout=self.timeout)
            tls = context.wrap_socket(raw, server_hostname=host)

            stream_id = connection.get_next_available_stream_id()
            connection.send_headers(
                stream_id,
                [
                    (":method", "GET"),
                    (":path", "/"),
                    (":scheme", scheme),
                    (":authority", host),
                    ("user-agent", "Basilisk/0.1"),
                ],
                end_stream=True,
            )
            tls.sendall(connection.data_to_send())

            tls.settimeout(self.timeout)
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                events = connection.receive_data(chunk)
                for event in events:
                    if isinstance(event, h2.events.PushedStreamReceived):
                        result.push_frames += 1
                        result.evidence.append(
                            f"server pushed stream {event.pushed_stream_id} "
                            f"(for stream {event.parent_stream_id})"
                        )
                    if isinstance(event, h2.events.RemoteSettingsChanged):
                        push = event.changed_settings.get(h2.settings.SettingCodes.ENABLE_PUSH)
                        if push is not None:
                            result.server_enable_push = push.new_value
            tls.close()
        except Exception as exc:
            logger.debug("HTTP/2 push probe failed for %s: %s", host, exc)
            result.evidence.append(f"h2 probe error: {exc}")
        return result

    def _header_fallback(self, host: str, port: int, scheme: str, result: PushInfo) -> PushInfo:
        try:
            import requests
            import urllib3

            urllib3.disable_warnings()
            response = requests.get(
                f"{scheme}://{host}",
                headers={"User-Agent": "Basilisk/0.1"},
                timeout=self.timeout,
                verify=False,
            )
            links = response.headers.get("Link", "")
            if "rel=preload" in links:
                result.preload_links = [part.strip() for part in links.split(",")]
                result.evidence.append(
                    "server sends Link: rel=preload hints — push-style resource delivery"
                )
            alt_svc = response.headers.get("Alt-Svc", "")
            if "h2" in alt_svc:
                result.evidence.append(f"Alt-Svc advertises HTTP/2: {alt_svc[:80]}")
        except Exception as exc:
            logger.debug("Push header fallback failed for %s: %s", host, exc)
        return result


def _wait_for_multiplexed_headers(host: str, port: int, timeout: float) -> tuple[str, dict]:
    """Best-effort GET over the best negotiated protocol (h2 first)."""
    if not HAS_HTTPX:
        return "", {}
    try:
        with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
            response = client.get(f"https://{host}:{port}/", headers={"User-Agent": "Basilisk/0.1"})
            return response.http_version or "", dict(response.headers)
    except Exception:
        return "", {}


def alt_svc_hints(host: str, port: int, timeout: float = 5.0) -> dict:
    """Return Alt-Svc / protocol hints advertised by the server."""
    _, headers = _wait_for_multiplexed_headers(host, port, timeout)
    result: dict = {}
    alt_svc = headers.get("alt-svc", "")
    if alt_svc:
        result["alt_svc"] = alt_svc[:300]
        for token in ("h3", "h2", "http/1.1"):
            if token in alt_svc:
                result[f"{token}_advertised"] = True
    return result


class Http2Client:
    """HTTP/2 request path via httpx[http2]. Falls back to HTTP/1.1."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        timeout: float = 5.0,
    ) -> ProtocolResult:
        result = ProtocolResult(protocol="h2")
        if not HAS_HTTPX:
            result.error = "httpx not installed"
            return result
        try:
            with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
                response = client.request(method.upper(), url, headers=headers)
            result.ok = True
            result.protocol = response.http_version or "h2"
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            result.body = response.text
        except Exception as exc:
            result.error = str(exc)
        return result


class Http3Client:
    """HTTP/3 request path via httpx[http3] QUIC transport (experimental)."""

    @property
    def available(self) -> bool:
        return HAS_HTTP3 and HAS_HTTPX

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        timeout: float = 5.0,
    ) -> ProtocolResult:
        result = ProtocolResult(protocol="h3")
        if not self.available:
            result.error = "http3 transport unavailable"
            return result
        try:
            transport = quic_transport.QuicTransport()
            with httpx.Client(transport=transport, timeout=timeout) as client:
                response = client.request(method.upper(), url, headers=headers)
            result.ok = True
            result.protocol = response.http_version or "h3"
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            result.body = response.text
        except Exception as exc:
            result.error = str(exc)
        return result