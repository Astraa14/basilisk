"""Scanning behind VPNs and bastion hosts — SSH dynamic proxy tunnel.

Spawns ``ssh -D`` as a local SOCKS5 proxy so scans traverse a bastion
host. Degrades gracefully when ssh is unavailable or the tunnel cannot
be established.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

TUNNEL_READY_TIMEOUT = 15.0
TUNNEL_PROBE_INTERVAL = 0.4


class TunnelError(RuntimeError):
    pass


@dataclass
class SshTunnel:
    user_at_host: str
    local_port: int = 0
    bind: str = "127.0.0.1"
    ssh_key: str = ""
    extra_options: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._port: int | None = None

    @staticmethod
    def ssh_available() -> bool:
        return shutil.which("ssh") is not None

    @property
    def proxy_url(self) -> str:
        if not self._port:
            return ""
        return f"socks5h://{self.bind}:{self._port}"

    def start(self) -> str:
        """Start the tunnel and wait until it accepts connections."""
        if not self.ssh_available():
            raise TunnelError("ssh binary not found on PATH — cannot open bastion tunnel")
        if not self.user_at_host or "@" not in self.user_at_host:
            raise TunnelError(f"invalid bastion target: {self.user_at_host!r}")

        self._port = self.local_port or self._pick_free_port()
        cmd = [
            "ssh",
            "-N",
            "-D",
            f"{self.bind}:{self._port}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ConnectTimeout=10",
        ]
        if self.ssh_key:
            cmd += ["-i", self.ssh_key]
        cmd += list(self.extra_options)
        cmd.append(self.user_at_host)

        logger.debug("Starting SSH tunnel: %s", " ".join(cmd))
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not self._wait_ready():
            self.stop()
            raise TunnelError(
                f"tunnel to {self.user_at_host} not ready within "
                f"{TUNNEL_READY_TIMEOUT}s (exit={self._process.poll()})"
            )
        return self.proxy_url

    def _wait_ready(self) -> bool:
        deadline = time.monotonic() + TUNNEL_READY_TIMEOUT
        while time.monotonic() < deadline:
            if self._process is None or self._process.poll() is not None:
                return False
            try:
                with socket.create_connection((self.bind, self._port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(TUNNEL_PROBE_INTERVAL)
        return False

    def _pick_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None
        self._port = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def open_bastion_tunnel(user_at_host: str) -> SshTunnel | None:
    """Convenience helper: start a tunnel or return None on failure."""
    try:
        tunnel = SshTunnel(user_at_host)
        tunnel.start()
        return tunnel
    except TunnelError as exc:
        logger.warning("Bastion tunnel unavailable: %s", exc)
        return None