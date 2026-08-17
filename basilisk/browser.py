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
    from selenium.common.exceptions import WebDriverException
    from selenium.webdriver.chrome.options import Options
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


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
    """Headless browser for client-side JS analysis and DOM fuzzing.

    Uses Playwright when available, otherwise falls back to Selenium.
    """

    def __init__(self, headless: bool = True, timeout: int = 15):
        self.headless = headless
        self.timeout = timeout
        self._driver = None
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._engine = None

    def start(self) -> bool:
        if HAS_PLAYWRIGHT:
            return self.start_playwright()
        return self.start_selenium()

    def start_playwright(self) -> bool:
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
            self._engine = "playwright"
            return True
        except Exception as e:
            logger.warning("Playwright browser init failed: %s", e)
            self._cleanup_playwright()
            return False

    def _cleanup_playwright(self) -> None:
        for closer in (self._context, self._browser):
            if closer is not None:
                try:
                    closer.close()
                except Exception:
                    pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
        self._context = None
        self._browser = None
        self._page = None
        self._playwright = None

    def start_selenium(self) -> bool:
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
            self._engine = "selenium"
            return True
        except WebDriverException as e:
            logger.warning("Chrome not available: %s", e)
            return False
        except Exception as e:
            logger.warning("Browser init failed: %s", e)
            return False

    def stop(self) -> None:
        if self._engine == "playwright":
            self._cleanup_playwright()
        elif self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None
        self._engine = None

    @property
    def engine(self) -> str:
        return self._engine or ""

    def analyze(self, url: str) -> BrowserResult:
        result = BrowserResult(url=url)
        if self._engine == "playwright":
            return self._analyze_playwright(url, result)
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

    def _analyze_playwright(self, url: str, result: BrowserResult) -> BrowserResult:
        if self._page is None:
            return result
        self._console_errors: list[str] = []
        self._page.on("console", lambda msg: self._console_errors.append(msg.text[:200]))
        try:
            start = time.monotonic()
            self._page.goto(
                url,
                wait_until="load",
                timeout=self.timeout * 1000,
            )
            result.load_time_ms = (time.monotonic() - start) * 1000
            time.sleep(0.5)
            result.rendered_html = self._page.content() or ""
            result.page_title = self._page.title() or ""
            result.cookies = [
                {"name": c.get("name", ""), "value": c.get("value", "")[:20]}
                for c in self._page.context.cookies()
            ]
            entries = self._page.evaluate(
                "() => window.performance.getEntries().map("
                "e => ({name: e.name, duration: e.duration, initiatorType: e.initiatorType}))"
            ) or []
            for entry in entries:
                result.network_requests.append({
                    "url": entry.get("name", "")[:100],
                    "duration_ms": entry.get("duration", 0) * 1000,
                    "type": entry.get("initiatorType", ""),
                })
            result.javascript_errors = list(self._console_errors)
        except Exception as e:
            logger.debug("Playwright analysis error for %s: %s", url, e)
        return result

    def fuzz_dom(self, url: str, payloads: list[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not self._driver and self._page is None:
            return findings
        payloads = payloads or DOM_XSS_PAYLOADS

        base_result = self.analyze(url)
        if not base_result.rendered_html:
            return findings

        dom_findings = self._scan_dom(base_result.rendered_html, url)
        findings.extend(dom_findings)

        for payload in payloads[:5]:
            fuzz_url = url + payload
            try:
                if self._engine == "playwright" and self._page is not None:
                    self._page.goto(fuzz_url, wait_until="load", timeout=self.timeout * 1000)
                    body = self._page.content() or ""
                else:
                    self._driver.get(fuzz_url)
                    body = self._driver.page_source or ""
                time.sleep(0.3)
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
        if self._engine == "playwright" and self._page is not None:
            try:
                return self._page.evaluate(script)
            except Exception:
                return None
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
    return HAS_SELENIUM or HAS_PLAYWRIGHT
