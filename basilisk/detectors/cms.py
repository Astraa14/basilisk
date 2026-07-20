"""CMS-specific vulnerability detection — WordPress, Drupal, Joomla, etc."""

from __future__ import annotations

import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


CMS_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "wordpress", "wp-admin"],
    "Drupal": ["drupal", "sites/default", "drupal.js", "core/misc"],
    "Joomla": ["joomla", "com_content", "option=com_", "components/com_"],
    "Magento": ["magento", "skin/frontend", "js/mage", "mage/"],
    "Shopify": ["shopify", "myshopify", "cdn.shopify"],
    "Wix": ["wix", "wixstatic"],
    "Squarespace": ["squarespace", "static.squarespace"],
    "Ghost": ["ghost", "ghost.io"],
    "Umbraco": ["umbraco", "umbraco/"],
    "Concrete5": ["concrete5", "concrete/"],
}

CMS_VULN_PATHS: dict[str, list[str]] = {
    "WordPress": [
        "/wp-admin/", "/wp-login.php", "/wp-config.php.bak",
        "/wp-content/debug.log", "/wp-json/wp/v2/users",
        "/readme.html", "/wp-cron.php",
    ],
    "Drupal": [
        "/user/register", "/node/1", "/CHANGELOG.txt",
        "/README.txt", "/install.php",
    ],
    "Joomla": [
        "/administrator/", "/configuration.php.bak",
        "/htaccess.txt", "/CHANGELOG.php",
    ],
}

CMS_VERSION_PATTERNS: dict[str, str] = {
    "WordPress": r"(?i)wordpress\s*(\d+\.\d+(?:\.\d+)?)",
    "Drupal": r"(?i)drupal\s*(\d+\.\d+(?:\.\d+)?)",
    "Joomla": r"(?i)joomla!\s*(\d+\.\d+(?:\.\d+)?)",
}


def detect_cms(body: str, headers: dict | None = None) -> tuple[str | None, str | None]:
    """Detect CMS type and version from response."""
    lower_body = body.lower() if body else ""
    detected = None
    version = None

    for cms, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig in lower_body:
                detected = cms
                break
        if detected:
            break

    if headers:
        x_powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        for cms, sigs in CMS_SIGNATURES.items():
            if cms.lower() in x_powered.lower():
                detected = cms
                break

    if detected and detected in CMS_VERSION_PATTERNS:
        match = re.search(CMS_VERSION_PATTERNS[detected], lower_body)
        if match:
            version = match.group(1)

    return detected, version


def detect_cms_vuln(
    response: dict, path: str, cms_type: str, target: str = ""
) -> Finding | None:
    status = response.get("status_code", 0)
    body = response.get("body", "")

    if status != 200:
        return None

    if path.endswith("wp-json/wp/v2/users"):
        try:
            import json
            users = json.loads(body)
            if isinstance(users, list) and len(users) > 0:
                cvss, vector = score_finding("cms")
                usernames = [u.get("name", "") for u in users[:5]]
                return Finding(
                    vulnerability=f"{cms_type}: User Enumeration",
                    severity="Medium",
                    description=f"WordPress REST API exposed {len(users)} user(s): {', '.join(usernames)}.",
                    target=target,
                    attack_type="cms",
                    payload=path,
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Disable REST API user endpoint or restrict access to authenticated users only.",
                )
        except Exception:
            pass

    if any(path.endswith(ext) for ext in [".bak", ".old", ".txt", ".log", ".php"]):
        if len(body) > 50:
            cvss, vector = score_finding("cms")
            return Finding(
                vulnerability=f"{cms_type}: Sensitive File Exposed",
                severity="High",
                description=f"Sensitive file exposed: {path} (HTTP {status}, {len(body)} bytes).",
                target=target,
                attack_type="cms",
                payload=path,
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Remove backup files and sensitive information from web-accessible directories.",
            )

    return None


def get_cms_paths(cms_type: str | None = None) -> list[str]:
    if cms_type and cms_type in CMS_VULN_PATHS:
        return list(CMS_VULN_PATHS[cms_type])
    all_paths: list[str] = []
    for paths in CMS_VULN_PATHS.values():
        all_paths.extend(paths)
    return list(dict.fromkeys(all_paths))


def get_cms_signatures() -> dict[str, list[str]]:
    return dict(CMS_SIGNATURES)
