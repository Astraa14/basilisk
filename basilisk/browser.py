"""Headless browser automation — client-side rendering analysis and DOM XSS."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from basilisk.detectors.dom_xss import DOM_SINKS, DOM_SOURCES, DOM_XSS_PAYLOADS
from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import WebDriverException
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False


@dataclass
class BrowserResult:
    url: str
    rendered_html: str = ""
    network_requests: list[dict] = field(default_factory=list)
    console_logs: list[str] = field(default_factory=list)
    screenshot_path: str = ""
    javascript_errors: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    page_title: str = ""
    load_time_ms: float = 0.0
    dom_scan_findings: list[Finding] = field(default_factory=list)


class BrowserAutomation:
    """Headless browser for client-side JS analysis and DOM fuzzing."""

    def __init__(self, headless: bool = True, timeout: int = 15):
        self.headless = headless
        self.timeout = timeout
        self._driver = None

    def start(self) -> bool:
        if not HAS_SELENIUM:
            return False
        try:
            opts = Options()
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--disable-web-security")
            opts.add_argument(f"--timeout={self.timeout * 1000}")
            opts.add_experimental_option("excludeSwitches", ["enable-logging"])
            self._driver = webdriver.Chrome(options=opts)
            self._driver.set_page_load_timeout(self.timeout)
            return True
        except WebDriverException as e:
            logger.warning("Chrome not available: %s", e)
            return False
        except Exception as e:
            logger.warning("Browser init failed: %s", e)
            return False

    def stop(self) -> None:
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    def analyze(self, url: str) -> BrowserResult:
        result = BrowserResult(url=url)
        if not self._driver:
            return result

        try:
            start = time.monotonic()
            self._driver.get(url)
            result.load_time_ms = (time.monotonic() - start) * 1000
            time.sleep(0.5)
            result.rendered_html = self._driver.page_source or ""
            result.page_title = self._driver.title or ""
            result.cookies = [{"name": c["name"], "value": c["value"][:20]} for c in self._driver.get_cookies()]

            logs = self._driver.execute_script("return window.performance.getEntries();") or []
            for entry in logs:
                if isinstance(entry, dict):
                    result.network_requests.append({
                        "url": entry.get("name", "")[:100],
                        "duration_ms": entry.get("duration", 0) * 1000,
                        "type": entry.get("initiatorType", ""),
                    })

            try:
                browser_logs = self._driver.get_log("browser")
                for entry in browser_logs:
                    msg = entry.get("message", "")
                    level = entry.get("level", "")
                    if level == "SEVERE":
                        result.javascript_errors.append(msg[:200])
                    result.console_logs.append(msg[:200])
            except Exception:
                pass

        except Exception as e:
            logger.debug("Browser analysis error for %s: %s", url, e)

        return result

    def fuzz_dom(self, url: str, payloads: list[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not self._driver:
            return findings
        payloads = payloads or DOM_XSS_PAYLOADS

        base_result = self.analyze(url)
        if not base_result.rendered_html:
            return findings

        dom_findings = self._scan_dom(base_result.rendered_html, url)
        findings.extend(dom_findings)

        for payload in payloads[:5]:
            fuzz_url = url + payload if "?" in url else url + payload
            try:
                self._driver.get(fuzz_url)
                time.sleep(0.3)
                body = self._driver.page_source or ""
                if payload[:20] in body:
                    cvss, vector = score_finding("dom_xss")
                    findings.append(
                        Finding(
                            vulnerability="DOM XSS via Browser Fuzzing",
                            severity="High",
                            description=f"Payload reflected in rendered DOM: {payload[:60]}",
                            target=fuzz_url,
                            attack_type="dom_xss",
                            payload=payload,
                            cvss_score=cvss,
                            cvss_vector=vector,
                            remediation="Contextually encode all data written to innerHTML/document.write.",
                        )
                    )
            except Exception:
                continue

        return findings

    def _scan_dom(self, html: str, url: str) -> list[Finding]:
        findings: list[Finding] = []
        for sink in DOM_SINKS:
            for source in DOM_SOURCES:
                pattern = re.compile(
                    rf".{{0,100}}{re.escape(source)}.{{0,100}}{re.escape(sink)}",
                    re.IGNORECASE,
                )
                if pattern.search(html):
                    cvss, vector = score_finding("dom_xss")
                    findings.append(
                        Finding(
                            vulnerability="DOM XSS Source-to-Sink Flow",
                            severity="High",
                            description=f"Data flow: {source} → {sink} detected in rendered JS.",
                            target=url,
                            attack_type="dom_xss",
                            cvss_score=cvss,
                            cvss_vector=vector,
                            remediation="Avoid dangerous DOM APIs. Use textContent instead of innerHTML.",
                        )
                    )
                    break
        return findings

    def execute_js(self, script: str) -> Any:
        if not self._driver:
            return None
        try:
            return self._driver.execute_script(script)
        except Exception:
            return None

    def get_all_links(self, url: str) -> list[str]:
        result = self.analyze(url)
        if not result.rendered_html:
            return []
        links = re.findall(r'href=[\'"]?(https?://[^\'" >]+)', result.rendered_html)
        return list(dict.fromkeys(links))


def is_browser_available() -> bool:
    return HAS_SELENIUM
