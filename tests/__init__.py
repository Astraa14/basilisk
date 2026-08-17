"""Shared test helpers — a thread-safe local HTTP server for transport tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _record(self):
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": "",
        }
        length = self.headers.get("Content-Length")
        if length:
            try:
                entry["body"] = self.rfile.read(int(length)).decode("utf-8", "replace")
            except Exception:
                pass
        self.server.requests.append(entry)

    def _send(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._record()
        if self.path.startswith("/redirect"):
            self._send(302, headers={"Location": self.path})
        elif self.path.startswith("/setcookie"):
            self._send(
                200,
                b"cookie set",
                {"Set-Cookie": "session=abc123; Path=/"},
            )
        elif self.path.startswith("/echo-headers"):
            headers = "|".join(
                f"{k}={v}" for k, v in self.headers.items() if k.lower().startswith(("authorization", "x-api", "cookie"))
            )
            self._send(200, headers.encode("utf-8"))
        elif self.path.startswith("/slow"):
            import time

            time.sleep(0.6)
            self._send(200, b"slow done")
        else:
            self._send(200, b"hello from test server")

    def do_POST(self):
        self._record()
        self._send(200, b"posted")

    do_PUT = do_POST
    do_HEAD = do_GET


class LocalServer:
    """Context manager spinning up a ThreadingHTTPServer on localhost."""

    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    @property
    def requests(self) -> list:
        return self.server.requests

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)