"""API endpoint enumeration — discover hidden API endpoints and schema paths."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

from basilisk.models import Finding
from basilisk.scoring import score_finding


COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/swagger", "/swagger.json", "/api-docs",
    "/openapi.json", "/docs", "/redoc",
    "/api/swagger", "/api/docs", "/api/openapi",
    "/rest", "/api/rest",
]

API_RESOURCE_COMMON = [
    "users", "user", "admin", "config", "status", "health",
    "info", "version", "metrics", "logs", "debug",
    "auth", "login", "register", "token", "oauth",
    "products", "orders", "payments", "invoices",
    "search", "upload", "download", "export", "import",
    "settings", "profile", "account", "billing",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


@dataclass
class APIEndpoint:
    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    body_preview: str = ""


@dataclass
class APIEnumResult:
    endpoints: list[APIEndpoint] = field(default_factory=list)
    api_base_url: str = ""
    auth_required: bool = False
    total_discovered: int = 0


class APIEnumerator:
    """Discover API endpoints by probing common paths and resources."""

    def __init__(self, base_url: str, fetch_fn: Callable | None = None):
        self.base_url = base_url.rstrip("/")
        self.fetch_fn = fetch_fn

    def enumerate(self) -> APIEnumResult:
        result = APIEnumResult()

        # First discover API base path
        api_base = self._discover_api_base()
        if api_base:
            result.api_base_url = api_base

        # Probe common resource paths
        for resource in API_RESOURCE_COMMON:
            for ext in ["", "/", "/1", "/list", "/all"]:
                path = f"{api_base or self.base_url}/{resource}{ext}"
                for method in ["GET", "POST", "OPTIONS"]:
                    ep = self._probe_endpoint(path, method)
                    if ep and ep.status_code not in (404, 405):
                        result.endpoints.append(ep)

        result.total_discovered = len(result.endpoints)
        return result

    def _discover_api_base(self) -> str:
        for path in COMMON_API_PATHS:
            url = urljoin(self.base_url, path)
            for method in ["GET", "OPTIONS"]:
                ep = self._probe_endpoint(url, method)
                if ep and ep.status_code not in (404, 405, 0):
                    # Check if response contains JSON
                    if ep.content_type and "json" in ep.content_type:
                        return url
                    return url
        return self.base_url

    def _probe_endpoint(self, url: str, method: str = "GET") -> APIEndpoint | None:
        if not self.fetch_fn:
            return None

        response = self.fetch_fn({"url": url, "method": method})
        if not response:
            return None

        body = response.get("body", "")
        return APIEndpoint(
            path=url,
            method=method,
            status_code=response.get("status_code", 0),
            content_type=response.get("headers", {}).get("Content-Type", ""),
            body_preview=body[:100],
        )


def analyze_enum_result(result: APIEnumResult, target: str = "") -> list[Finding]:
    """Analyze API enumeration results for security issues."""
    findings: list[Finding] = []

    for ep in result.endpoints:
        # Check for sensitive endpoints with no auth
        if ep.status_code in (200, 201) and ep.path.endswith(("admin", "config", "debug", "logs", "health")):
            cvss, vector = score_finding("info_disclosure")
            findings.append(
                Finding(
                    vulnerability="Exposed API Endpoint",
                    severity="Medium",
                    description=f"Potentially sensitive endpoint accessible: {ep.method} {ep.path} (HTTP {ep.status_code})",
                    target=target,
                    attack_type="api_enum",
                    payload=ep.path,
                    cvss_score=cvss,
                    cvss_vector=vector,
                )
            )

        # Check for Swagger/OpenAPI in production
        if ep.status_code == 200 and any(p in ep.path for p in ["swagger", "openapi", "api-docs"]):
            cvss, vector = score_finding("info_disclosure")
            findings.append(
                Finding(
                    vulnerability="API Documentation Exposed",
                    severity="Low",
                    description=f"API documentation exposed: {ep.path}. May leak endpoint structure.",
                    target=target,
                    attack_type="api_enum",
                    payload=ep.path,
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Disable API documentation in production or protect with authentication.",
                )
            )

    if result.total_discovered > 20:
        cvss, vector = score_finding("api_enum")
        findings.append(
            Finding(
                vulnerability="Large Attack Surface (API)",
                severity="Low",
                description=f"Discovered {result.total_discovered} API endpoints, indicating a large API attack surface.",
                target=target,
                attack_type="api_enum",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Minimize exposed API endpoints. Implement proper access controls on all endpoints.",
            )
        )

    return findings


def get_common_paths() -> list[str]:
    return list(COMMON_API_PATHS)

def get_common_resources() -> list[str]:
    return list(API_RESOURCE_COMMON)

def get_methods() -> list[str]:
    return list(HTTP_METHODS)
