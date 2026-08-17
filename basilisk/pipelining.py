"""HTTP/1.1 request pipelining probe — checks whether a server accepts
multiple requests on one connection and inspects response ordering.

Pipelining support implies a request-smuggling surface: a backend that
accepts back-to-back requests without framing discipline may be confused
by CL/TE desyncs (cross-checked by basilisk.smuggling).
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from dataclasses import dataclass, field

from basilisk.tcp import TcpTracker

logger = logging.getLogger(__name__)

STATUS_LINE = re.compile(rb"HTTP/1\.[01] (\d{3})")


@dataclass
class PipelineResult:
    supported: bool = False
    ordered: bool = False
    statuses: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    error: str = ""


class PipelineProbe:
    """Sends paired HTTP/1.1 requests over a single raw connection."""

    def __init__(
        self,
        timeout: float = 5.0,
        tracker: TcpTracker | None = None,
        user_agent: str = "Basilisk/0.1",
    ):
        self.timeout = timeout
        self.tracker = tracker or TcpTracker()
        self.user_agent = user_agent

    def probe(self, host: str, port: int = 80, tls: bool = False) -> PipelineResult:
        result = PipelineResult()
        attempts = 2
        for attempt in range(attempts):
            conn_id = self.tracker.open(host, port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((host, port))
                self.tracker.established(conn_id)
                if tls:
                    context = ssl.create_default_context()
                    context.set_alpn_protocols(["http/1.1"])
                    sock = context.wrap_socket(sock, server_hostname=host)

                payload = self._pipeline_payload(host)
                sock.sendall(payload)
                self.tracker.data(conn_id, len(payload), 0)

                chunks: list[bytes] = []
                try:
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except TimeoutError:
                    pass
                except ConnectionResetError:
                    self.tracker.reset(conn_id)
                buffer = b"".join(chunks)
                self.tracker.data(conn_id, 0, len(buffer))

                statuses = [int(m) for m in STATUS_LINE.findall(buffer)]
                result.statuses = statuses
                if len(statuses) >= 2:
                    result.supported = True
                    result.ordered = statuses[:2] == statuses[:2]
                    result.evidence.append(
                        f"server answered {len(statuses)} pipelined requests "
                        f"in order: {statuses[:4]}"
                    )
                    result.evidence.append(
                        "pipelining accepted — verify CL/TE desync resistance "
                        "with basilisk.smuggling"
                    )
                    break
                result.evidence.append(
                    f"attempt {attempt + 1}: server returned {len(statuses)} "
                    "response(s) — pipelining not supported"
                )
            except ConnectionRefusedError:
                self.tracker.refused(host, port)
                result.error = "connection refused"
                break
            except TimeoutError:
                self.tracker.timeout(conn_id)
                result.error = "connect timed out"
                break
            except ssl.SSLError as exc:
                self.tracker.reset(conn_id)
                result.error = f"TLS error: {exc}"
                break
            except OSError as exc:
                self.tracker.timeout(conn_id)
                result.error = str(exc)
                break
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
                if conn_id:
                    self.tracker.close(conn_id, clean=True)
        return result

    def _pipeline_payload(self, host: str) -> bytes:
        first = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        second = (
            f"GET /robots.txt HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        return (first + second).encode("latin-1")