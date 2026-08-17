"""TCP connection state tracking and anomaly detection.

Tracks the lifecycle of raw connections opened by transport probes and
flags instability patterns: resets, refusals, half-open sockets, and
excessive connection churn.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ConnectionState(str, Enum):
    SYN_SENT = "syn_sent"
    ESTABLISHED = "established"
    DATA_TRANSFER = "data_transfer"
    CLOSED = "closed"
    RESET = "reset"
    REFUSED = "refused"
    TIMEOUT = "timeout"


@dataclass
class TrackedConnection:
    conn_id: int
    host: str
    port: int
    state: ConnectionState = ConnectionState.SYN_SENT
    opened_at: float = 0.0
    established_at: float | None = None
    closed_at: float | None = None
    connect_ms: float = 0.0
    lifecycle_ms: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0


class TcpTracker:
    """Thread-safe registry of connection lifecycles with anomaly rules."""

    RESET_RATIO_THRESHOLD = 0.3
    REFUSED_RATIO_THRESHOLD = 0.3
    MIN_SAMPLE = 4
    CHURN_WINDOW = 10.0
    CHURN_LIMIT = 12

    def __init__(self):
        self._conns: dict[int, TrackedConnection] = {}
        self._lock = threading.Lock()
        self._next_id = 1

    def _new_id(self) -> int:
        conn_id = self._next_id
        self._next_id += 1
        return conn_id

    def open(self, host: str, port: int) -> int:
        with self._lock:
            conn_id = self._new_id()
            self._conns[conn_id] = TrackedConnection(
                conn_id=conn_id, host=host, port=port, opened_at=time.monotonic()
            )
            return conn_id

    def _update(self, conn_id: int, **changes) -> None:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                return
            for key, value in changes.items():
                setattr(conn, key, value)

    def established(self, conn_id: int) -> None:
        now = time.monotonic()
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                return
            conn.state = ConnectionState.ESTABLISHED
            conn.established_at = now
            conn.connect_ms = (now - conn.opened_at) * 1000.0

    def data(self, conn_id: int, bytes_sent: int = 0, bytes_recv: int = 0) -> None:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                return
            conn.state = ConnectionState.DATA_TRANSFER
            conn.bytes_sent += bytes_sent
            conn.bytes_recv += bytes_recv

    def close(self, conn_id: int, clean: bool = True) -> None:
        now = time.monotonic()
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                return
            conn.closed_at = now
            conn.lifecycle_ms = (now - conn.opened_at) * 1000.0
            if conn.state is ConnectionState.SYN_SENT and not clean:
                conn.state = ConnectionState.TIMEOUT
            elif clean:
                conn.state = ConnectionState.CLOSED
            elif conn.state in (ConnectionState.ESTABLISHED, ConnectionState.DATA_TRANSFER):
                conn.state = ConnectionState.RESET

    def reset(self, conn_id: int) -> None:
        self._update(conn_id, state=ConnectionState.RESET, closed_at=time.monotonic())

    def refused(self, host: str, port: int) -> int:
        with self._lock:
            conn_id = self._new_id()
            self._conns[conn_id] = TrackedConnection(
                conn_id=conn_id,
                host=host,
                port=port,
                state=ConnectionState.REFUSED,
                opened_at=time.monotonic(),
                closed_at=time.monotonic(),
            )
            return conn_id

    def timeout(self, conn_id: int) -> None:
        self._update(conn_id, state=ConnectionState.TIMEOUT, closed_at=time.monotonic())

    # ── aggregation ───────────────────────────────────────────────────────

    def snapshot(self) -> list[TrackedConnection]:
        with self._lock:
            return list(self._conns.values())

    def report(self) -> tuple[dict, list[dict]]:
        """Return (stats, anomalies) where anomalies carry human-readable labels."""
        conns = self.snapshot()
        stats: dict = {
            "total": len(conns),
            "hosts": sorted({c.host for c in conns}),
            "states": dict(Counter(c.state.value for c in conns)),
            "avg_connect_ms": 0.0,
            "avg_lifecycle_ms": 0.0,
        }
        established = [c for c in conns if c.established_at is not None]
        closed_durations = [c.lifecycle_ms for c in conns if c.lifecycle_ms > 0]
        if established:
            stats["avg_connect_ms"] = round(
                sum(c.connect_ms for c in established) / len(established), 2
            )
        if closed_durations:
            stats["avg_lifecycle_ms"] = round(
                sum(closed_durations) / len(closed_durations), 2
            )

        anomalies: list[dict] = []
        n = len(conns)
        if n < self.MIN_SAMPLE:
            return stats, anomalies

        counts = Counter(c.state for c in conns)
        resets = counts[ConnectionState.RESET]
        refused = counts[ConnectionState.REFUSED]
        timeouts = counts[ConnectionState.TIMEOUT]

        if resets / n > self.RESET_RATIO_THRESHOLD:
            anomalies.append(
                {
                    "label": "Excessive TCP resets",
                    "severity": "Low",
                    "detail": f"{resets}/{n} connections ended with RST — "
                    "possible WAF, firewall, or unstable backend",
                }
            )
        if refused / n > self.REFUSED_RATIO_THRESHOLD:
            anomalies.append(
                {
                    "label": "Intermittent connection refusals",
                    "severity": "Medium",
                    "detail": f"{refused}/{n} connections refused — "
                    "service may be firewalled or overloaded",
                }
            )
        if timeouts >= 3:
            anomalies.append(
                {
                    "label": "Half-open connections",
                    "severity": "Low",
                    "detail": f"{timeouts} connections timed out mid-handshake "
                    "— potential SYN-flood filtering or network issues",
                }
            )

        now = time.monotonic()
        recent_by_host: dict[tuple, list[float]] = {}
        for c in conns:
            recent_by_host.setdefault((c.host, c.port), []).append(c.opened_at)
        for endpoint, times in recent_by_host.items():
            recent = [t for t in times if now - t <= self.CHURN_WINDOW]
            if len(recent) > self.CHURN_LIMIT:
                anomalies.append(
                    {
                        "label": "Excessive connection churn",
                        "severity": "Low",
                        "detail": f"{len(recent)} connections to {endpoint[0]}:{endpoint[1]} "
                        "within 10s — connection pooling / keep-alive may be broken",
                    }
                )

        # Alternating success/failure pattern suggests filtering.
        ordered = sorted(conns, key=lambda c: c.opened_at)
        transitions = 0
        last_ok = None
        for c in ordered:
            ok = c.state not in (ConnectionState.REFUSED, ConnectionState.TIMEOUT)
            if last_ok is not None and ok != last_ok:
                transitions += 1
            last_ok = ok
        if transitions >= 4:
            anomalies.append(
                {
                    "label": "Unstable connectivity pattern",
                    "severity": "Low",
                    "detail": f"connectivity flapped {transitions} times — "
                    "rate limiting, failover, or firewall rules suspected",
                }
            )

        return stats, anomalies


class TcpProber:
    """Opens real connections to gather TCP behavior against a target."""

    def __init__(self, tracker: TcpTracker | None = None, timeout: float = 3.0):
        self.tracker = tracker or TcpTracker()
        self.timeout = timeout

    def probe(self, host: str, port: int, attempts: int = 5, send_bytes: bytes = b"") -> dict:
        """Run several connect/send/close cycles and report aggregate stats."""
        for _ in range(attempts):
            conn_id = self.tracker.open(host, port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((host, port))
                self.tracker.established(conn_id)
                sent = 0
                recv = 0
                if send_bytes:
                    sock.sendall(send_bytes)
                    sent = len(send_bytes)
                    try:
                        data = sock.recv(1024)
                        recv = len(data)
                    except TimeoutError:
                        pass
                    except ConnectionResetError:
                        self.tracker.reset(conn_id)
                self.tracker.data(conn_id, sent, recv)
                sock.close()
                self.tracker.close(conn_id, clean=True)
            except ConnectionRefusedError:
                self.tracker.refused(host, port)
            except TimeoutError:
                self.tracker.timeout(conn_id)
            except OSError as exc:
                logger.debug("TCP probe error %s:%s: %s", host, port, exc)
                self.tracker.timeout(conn_id)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        stats, anomalies = self.tracker.report()
        return {"endpoint": f"{host}:{port}", "stats": stats, "anomalies": anomalies}