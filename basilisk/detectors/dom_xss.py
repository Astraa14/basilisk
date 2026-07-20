"""DOM-based XSS detection — client-side sink analysis and headless browser patterns."""

from __future__ import annotations

import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "execScript", "msSetImmediate(",
    "location", "location.href", "location.hash", "location.search",
    "location.pathname", "location.assign(", "location.replace(",
    "srcdoc", "postMessage(", "onmessage",
]

DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "location", "location.href", "location.search", "location.hash",
    "location.pathname", "document.referrer",
    "window.name", "history.pushState", "history.replaceState",
    "postMessage", "localStorage", "sessionStorage",
]

DOM_XSS_PAYLOADS = [
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "#javascript:alert(1)",
    "?name=<script>alert(1)</script>",
    "?q=<img src=x onerror=alert(1)>",
    "#__proto__[x]=<script>alert(1)</script>",
    "?__proto__[x]=<img src=x onerror=alert(1)>",
    "?__proto__.toString=<script>alert(1)</script>",
    "#onerror=alert(1)//",
    "?<script>alert(1)</script>",
]

DOM_SOURCE_PATTERNS = {
    "hash": r"location\.hash|location\.href",
    "search": r"location\.search|window\.location",
    "referrer": r"document\.referrer",
    "postMessage": r"addEventListener\(['\"]message['\"]",
}


def analyze_script_for_dom_xss(
    script_content: str,
    url: str = "",
) -> list[Finding]:
    findings: list[Finding] = []

    for sink in DOM_SINKS:
        for source in DOM_SOURCES:
            pattern = re.compile(
                rf".{{0,50}}{re.escape(source)}.{{0,50}}{re.escape(sink)}",
                re.IGNORECASE,
            )
            if pattern.search(script_content):
                cvss, vector = score_finding("dom_xss")
                findings.append(
                    Finding(
                        vulnerability="DOM-based XSS (Source-to-Sink)",
                        severity="High",
                        description=f"Data flow from {source} to {sink} detected. User input reaches dangerous DOM sink.",
                        target=url,
                        attack_type="dom_xss",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Avoid using innerHTML, document.write, and eval(). Use safe DOM APIs like textContent.",
                    )
                )
                break

    return findings


def detect_dom_xss_reflection(
    response: dict, payload: str, target: str = ""
) -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)
    lower_body = body.lower()
    lower_payload = payload.lower()

    stripped = re.sub(r"[#?]", "", lower_payload)
    if stripped and stripped in lower_body:
        cvss, vector = score_finding("dom_xss")
        return Finding(
            vulnerability="DOM-based XSS (Reflection Detected)",
            severity="High",
            description=f"Payload reflected in page body: {payload[:60]}",
            target=target,
            attack_type="dom_xss",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Contextually encode all data written to the DOM. Use Content Security Policy (CSP).",
        )

    return None


def get_payloads() -> list[str]:
    return list(DOM_XSS_PAYLOADS)

def get_sinks() -> list[str]:
    return list(DOM_SINKS)

def get_sources() -> list[str]:
    return list(DOM_SOURCES)
