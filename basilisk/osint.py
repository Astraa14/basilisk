"""OSINT integration — detect leaked credentials, exposed APIs, and public assets."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

GITHUB_SECRET_PATTERNS = [
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Access Token"),
    (r"github_pat_[0-9a-zA-Z]{22,}", "GitHub Fine-Grained Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
    (r"(?i)api[_-]?key[\s\"'=:]+[0-9a-zA-Z]{16,}", "Generic API Key"),
    (r"(?i)-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)token[\s\"'=:]+[0-9a-zA-Z._-]{8,}", "Generic Token"),
    (r"(?i)password[\s\"'=:]+[^\"'\s]{8,}", "Plaintext Password"),
    (r"(?i)secret[\s\"'=:]+[0-9a-zA-Z]{16,}", "Generic Secret"),
    (r"sqlite:///|mysql://|postgresql://|mongodb://[^/\s]+:[^@\s]+@", "Database Connection String"),
]

PUBLIC_ASSET_INDICATORS = [
    "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
    "cloudfront.net", "cdn.", "amazonaws.com/",
]

COMMON_LEAK_ENDPOINTS = [
    "/.env", "/.git/config", "/.gitignore", "/.htaccess",
    "/config.json", "/config.php", "/database.yml",
    "/credentials.json", "/secrets.yml", "/.npmrc",
    "/.dockerenv", "/composer.json", "/wp-config.php.bak",
]


@dataclass
class OSINTResult:
    leaked_secrets: list[dict] = field(default_factory=list)
    exposed_assets: list[str] = field(default_factory=list)
    emails_found: list[str] = field(default_factory=list)
    subdomains_found: list[str] = field(default_factory=list)
    s3_buckets: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class OSINTCollector:
    """Collect open-source intelligence — leaks, exposed assets, secrets."""

    def __init__(self, domain: str, fetch_fn=None):
        self.domain = domain.lower().strip()
        self.fetch_fn = fetch_fn or self._default_fetch
        self.session = requests.Session() if HAS_REQUESTS else None
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; BasiliskOSINT/2.0)"})

    def _default_fetch(self, url: str) -> dict | None:
        if not self.session:
            return None
        try:
            resp = self.session.get(url, timeout=10)
            return {"body": resp.text, "status_code": resp.status_code, "headers": dict(resp.headers)}
        except Exception:
            return None

    def collect(self, deep: bool = False) -> OSINTResult:
        result = OSINTResult()
        self._scan_common_endpoints(result)
        self._analyze_page_source(result)
        return result

    def _scan_common_endpoints(self, result: OSINTResult) -> None:
        for path in COMMON_LEAK_ENDPOINTS:
            url = f"https://{self.domain}{path}"
            resp = self.fetch_fn(url)
            if not resp or resp.get("status_code") != 200:
                continue
            body = resp.get("body", "")
            self._check_secrets_in_body(body, url, result)

    def _analyze_page_source(self, result: OSINTResult) -> None:
        for proto in ("https://", "http://"):
            url = f"{proto}{self.domain}"
            resp = self.fetch_fn(url)
            if not resp:
                continue
            body = resp.get("body", "")
            self._extract_emails(body, result)
            self._check_secrets_in_body(body, url, result)
            self._detect_assets(body, result)
            self._extract_js_endpoints(body, result)
            break

    def _check_secrets_in_body(self, body: str, source: str, result: OSINTResult) -> None:
        for pattern, name in GITHUB_SECRET_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches[:3]:
                redacted = match[:8] + "..." + match[-4:]
                result.leaked_secrets.append({
                    "type": name,
                    "value": redacted,
                    "source": source[:100],
                })
                cvss, vector = score_finding("info_disclosure")
                result.findings.append(
                    Finding(
                        vulnerability=f"OSINT: {name} Leaked",
                        severity="Critical" if "PRIVATE KEY" in name or "password" in name.lower() else "High",
                        description=f"{name} found in publicly accessible content at {source[:80]}: {redacted}",
                        target=source,
                        attack_type="info_disclosure",
                        payload=redacted,
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Revoke the exposed credential immediately. Implement secret scanning in CI/CD.",
                    )
                )

    def _extract_emails(self, body: str, result: OSINTResult) -> None:
        emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))
        for email in emails:
            if email.endswith(f".{self.domain.split('.')[-1]}") or self.domain in email:
                result.emails_found.append(email)

    def _detect_assets(self, body: str, result: OSINTResult) -> None:
        for indicator in PUBLIC_ASSET_INDICATORS:
            if indicator in body:
                urls = re.findall(rf'https?://[^"\'<> ]*{re.escape(indicator)}[^"\'<> ]*', body)
                for url in urls[:5]:
                    result.exposed_assets.append(url)
                    if "s3" in indicator or "storage" in indicator:
                        result.s3_buckets.append(url)

        if result.s3_buckets:
            cvss, vector = score_finding("info_disclosure")
            result.findings.append(
                Finding(
                    vulnerability=f"OSINT: Public Cloud Storage Buckets ({len(result.s3_buckets)})",
                    severity="Medium",
                    description=f"Found {len(result.s3_buckets)} public cloud storage references. Possible data leakage: {result.s3_buckets[0][:80]}",
                    target=f"https://{self.domain}",
                    attack_type="info_disclosure",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Review bucket permissions. Ensure no public read access to sensitive data.",
                )
            )

    def _extract_js_endpoints(self, body: str, result: OSINTResult) -> None:
        api_patterns = re.findall(r'["\'](/api/[a-zA-Z0-9/_\-{}]+)["\']', body)
        for api_path in set(api_patterns):
            if len(api_path) > 10 and "{" not in api_path:
                result.subdomains_found.append(api_path[:100])


def search_github(org: str, token: str | None = None) -> list[dict]:
    """Search GitHub for exposed secrets in an organization."""
    if not HAS_REQUESTS:
        return []
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    results: list[dict] = []
    try:
        resp = requests.get(
            f"https://api.github.com/search/code?q=org:{org}+api_key&per_page=10",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            for item in items:
                results.append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                })
    except Exception as e:
        logger.debug("GitHub search failed: %s", e)
    return results


def get_secret_patterns() -> list[tuple[str, str]]:
    return list(GITHUB_SECRET_PATTERNS)

def get_leak_endpoints() -> list[str]:
    return list(COMMON_LEAK_ENDPOINTS)
