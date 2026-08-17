"""
Ephemeral local web server for Basilisk live session dashboard.

Spawns a local HTTP server bound strictly to 127.0.0.1 on an auto-assigned port.
Serves a code-authenticated live UI for the duration of the CLI session.
When the CLI process exits or the session finishes, the server terminates.
"""

from __future__ import annotations

import json
import logging
import random
import string
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


def generate_passcode(length: int = 6) -> str:
    """Generate a readable 6-character uppercase passcode (e.g., BSK-8492)."""
    digits = "".join(random.choices(string.digits, k=4))
    letters = "".join(random.choices(string.ascii_uppercase, k=2))
    return f"BSK-{letters}{digits}"


class SessionState:
    """Thread-safe state container for an ephemeral scan session."""

    def __init__(self, target_url: str, passcode: str):
        self.target_url = target_url
        self.passcode = passcode
        self.auth_tokens: set[str] = set()
        self.status = "initializing"
        self.progress_msg = "Starting scan..."
        self.pages_scanned = 0
        self.forms_found = 0
        self.findings: list[dict] = []
        self.logs: list[str] = []
        self.completed = False
        self._lock = threading.Lock()

    def update_progress(self, msg: str) -> None:
        with self._lock:
            self.progress_msg = msg
            self.status = "scanning"
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def set_report(self, report: dict) -> None:
        with self._lock:
            self.pages_scanned = report.get("pages_scanned", 0)
            self.forms_found = report.get("forms_found", 0)
            self.findings = report.get("findings", [])
            self.status = "completed"
            self.completed = True
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] Scan completed.")

    def add_finding(self, finding: dict) -> None:
        with self._lock:
            self.findings.append(finding)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "target_url": self.target_url,
                "status": self.status,
                "progress_msg": self.progress_msg,
                "pages_scanned": self.pages_scanned,
                "forms_found": self.forms_found,
                "findings": self.findings,
                "logs": self.logs[-50:],
                "completed": self.completed,
            }


class EphemeralDashboardHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler serving the ephemeral single-page web UI."""

    session: SessionState | None = None

    def log_message(self, format: str, *args: float | str | int | tuple[str, ...]) -> None:
        """Suppress default stdout HTTP log noise."""
        pass

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_content: str, status: int = 200) -> None:
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _is_authenticated(self) -> bool:
        if not self.session:
            return False
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "bsk_token" and v in self.session.auth_tokens:
                    return True
        # Check query param auth
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        code = qs.get("code", [None])[0]
        if code and code == self.session.passcode:
            return True
        return False

    def do_GET(self) -> None:
        if not self.session:
            self._send_json({"error": "No active session"}, 404)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            from basilisk.web_ui import GET_DASHBOARD_HTML
            self._send_html(GET_DASHBOARD_HTML())
            return

        if path == "/api/session":
            if not self._is_authenticated():
                self._send_json({"error": "Unauthorized"}, 401)
                return
            self._send_json(self.session.to_dict())
            return

        if path == "/api/ping":
            self._send_json({"active": True, "target": self.session.target_url})
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        if not self.session:
            self._send_json({"error": "No active session"}, 404)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else "{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}

            code = (data.get("code") or "").strip().upper()
            if code == self.session.passcode:
                token = f"token_{random.randint(10000000, 99999999)}"
                self.session.auth_tokens.add(token)
                
                body = json.dumps({"success": True, "token": token}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"bsk_token={token}; Path=/; HttpOnly; SameSite=Strict")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send_json({"success": False, "error": "Invalid passcode"}, 401)
            return

        self._send_json({"error": "Not found"}, 404)


class EphemeralDashboardServer:
    """Controller for the live local web dashboard server."""

    def __init__(self, target_url: str, port: int = 0):
        self.passcode = generate_passcode()
        self.session = SessionState(target_url=target_url, passcode=self.passcode)
        
        # Custom handler class bound to this session
        class BoundHandler(EphemeralDashboardHandler):
            session = self.session

        self.server = HTTPServer(("127.0.0.1", port), BoundHandler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.autologin_url = f"{self.url}/?code={self.passcode}"
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        """Start server in background daemon thread."""
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def open_browser(self) -> None:
        """Open web browser to autologin URL."""
        webbrowser.open(self.autologin_url)

    def stop(self) -> None:
        """Shutdown and close server."""
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
