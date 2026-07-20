"""WebSocket fuzzing and injection detection."""

from __future__ import annotations

import json
import random
import string

from basilisk.models import Finding
from basilisk.scoring import score_finding


WEBSOCKET_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../etc/passwd",
    "{{7*7}}",
    '{"query":"{__schema{types{name}}}"}',
    '{"operation":"subscribe","id":"1"}',
    '{"event":"join","room":"admin"}',
    "GARBAGE\x00DATA",
    "A" * 10000,
    " " * 1000,
]

WS_ERROR_SIGNATURES = [
    "websocket", "ws://", "wss://", "ws.onmessage", "ws.send",
    "socket.io", "pusher", "socketcluster",
    "upgrade: websocket", "sec-websocket",
]


def detect_websocket_endpoint(response: dict) -> bool:
    headers = response.get("headers", {})
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    upgrade = lower.get("upgrade", "")
    connection = lower.get("connection", "")
    return "websocket" in upgrade or "upgrade" in connection


def detect_websocket_vuln(
    response: dict, payload: str, endpoint: str = ""
) -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)
    target = response.get("url", endpoint)
    lower_body = body.lower()

    if payload in body:
        cvss, vector = score_finding("websocket")
        return Finding(
            vulnerability="WebSocket Message Reflection (XSS)",
            severity="High",
            description=f"Payload reflected in WebSocket response: {payload[:60]}",
            target=target,
            attack_type="websocket",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Sanitize WebSocket messages server-side before broadcasting.",
        )

    error_indicators = ["internal error", "stack trace", "exception", "traceback"]
    if status == 500 or any(e in lower_body for e in error_indicators):
        cvss, vector = score_finding("websocket")
        return Finding(
            vulnerability="WebSocket Server Error",
            severity="Medium",
            description=f"WebSocket endpoint returned error for payload: {payload[:60]}",
            target=target,
            attack_type="websocket",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
        )

    return None


def get_payloads() -> list[str]:
    return list(WEBSOCKET_PAYLOADS)
