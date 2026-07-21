"""Automatic security test case generation from OpenAPI/Swagger specs."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

COMMON_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api/openapi.json", "/api/swagger.json", "/api-docs",
    "/docs/json", "/swagger-resources", "/v2/api-docs",
    "/v3/api-docs", "/openapi.yaml", "/swagger.yaml",
]

SENSITIVE_PARAMS = ["password", "secret", "token", "api_key", "apikey",
                    "ssn", "credit_card", "cvv", "pin", "authorization"]

COMMON_PAYLOADS: dict[str, list[str]] = {
    "sqli": ["' OR 1=1--", "' UNION SELECT NULL--", "1' AND 1=1--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "cmdi": [";id", "|id", "`id`"],
    "ssrf": ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"],
}

PARAM_FUZZ_VALUES = {
    "integer": [0, -1, 999999, "abc", None],
    "string": ["", "A" * 10000, "<script>alert(1)</script>", "../../etc/passwd"],
    "number": [0, -1, 1.7976931348623157e308, "NaN"],
    "boolean": [True, False, None, "true", 1],
    "array": [[], [None], ["A" * 1000]],
}


@dataclass
class OpenAPIEndpoint:
    path: str
    method: str
    parameters: list[dict] = field(default_factory=list)
    request_body: dict | None = None
    security: list[dict] = field(default_factory=list)


@dataclass
class OpenAPIAnalysis:
    spec_url: str = ""
    endpoints: list[OpenAPIEndpoint] = field(default_factory=list)
    endpoints_without_auth: list[OpenAPIEndpoint] = field(default_factory=list)
    sensitive_params_exposed: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class OpenAPITestGenerator:
    """Parse OpenAPI specs and generate security test cases."""

    def __init__(self, fetch_fn: Callable | None = None):
        self.fetch_fn = fetch_fn

    def discover_and_analyze(self, base_url: str) -> OpenAPIAnalysis:
        analysis = OpenAPIAnalysis()
        spec_url = self._discover_spec(base_url)
        if not spec_url:
            return analysis

        analysis.spec_url = spec_url
        spec = self._fetch_spec(spec_url)
        if not spec:
            return analysis

        self._parse_spec(spec, analysis)
        self._analyze_security(analysis, base_url)
        return analysis

    def _discover_spec(self, base_url: str) -> str | None:
        for path in COMMON_SPEC_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            if self.fetch_fn:
                try:
                    resp = self.fetch_fn({"url": url, "method": "GET"})
                    if resp and resp.get("status_code") == 200:
                        body = resp.get("body", "")
                        if "openapi" in body[:500] or "swagger" in body[:500]:
                            return url
                except Exception:
                    continue
        return None

    def _fetch_spec(self, url: str) -> dict | None:
        if not self.fetch_fn:
            return None
        try:
            resp = self.fetch_fn({"url": url, "method": "GET"})
            if resp:
                return json.loads(resp.get("body", "{}"))
        except (json.JSONDecodeError, TypeError, Exception) as e:
            logger.debug("Failed to parse spec: %s", e)
        return None

    def _parse_spec(self, spec: dict, analysis: OpenAPIAnalysis) -> None:
        paths = spec.get("paths", {})
        root_security = spec.get("security", [])
        if not isinstance(root_security, list):
            root_security = []

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in ["get", "post", "put", "delete", "patch", "options"]:
                operation = methods.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                params = operation.get("parameters", [])
                if isinstance(params, list):
                    params = [p for p in params if isinstance(p, dict)]

                request_body = operation.get("requestBody")
                security = operation.get("security", root_security)
                if not isinstance(security, list):
                    security = []

                ep = OpenAPIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=params,
                    request_body=request_body,
                    security=security,
                )
                analysis.endpoints.append(ep)

        components = spec.get("components", spec.get("definitions", {}))
        security_defs = components.get("securitySchemes", {}) if isinstance(components, dict) else {}

    def _analyze_security(self, analysis: OpenAPIAnalysis, base_url: str) -> None:
        for ep in analysis.endpoints:
            param_names = [p.get("name", "") for p in ep.parameters]
            for pname in param_names:
                if any(s in pname.lower() for s in SENSITIVE_PARAMS):
                    analysis.sensitive_params_exposed.append(f"{ep.method} {ep.path}:{pname}")

            if not ep.security and ep.method in ("POST", "PUT", "DELETE", "PATCH"):
                analysis.endpoints_without_auth.append(ep)

        for ep in analysis.endpoints_without_auth:
            cvss, vector = score_finding("info_disclosure")
            analysis.findings.append(
                Finding(
                    vulnerability="Unauthenticated API Endpoint",
                    severity="Medium",
                    description=f"Endpoint {ep.method} {ep.path} has no security requirements in OpenAPI spec.",
                    target=analysis.spec_url,
                    attack_type="api_enum",
                    payload=f"{ep.method} {ep.path}",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Add authentication requirements to all protected endpoints.",
                )
            )

        for param in analysis.sensitive_params_exposed:
            cvss, vector = score_finding("info_disclosure")
            analysis.findings.append(
                Finding(
                    vulnerability="Sensitive Parameter in API Spec",
                    severity="High",
                    description=f"Sensitive parameter '{param}' exposed in OpenAPI specification.",
                    target=analysis.spec_url,
                    attack_type="api_enum",
                    payload=param,
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Avoid documenting sensitive parameters. Use header-based auth instead.",
                )
            )

    def generate_tests(self, analysis: OpenAPIAnalysis) -> list[dict]:
        tests: list[dict] = []
        for ep in analysis.endpoints:
            for vuln_type, payloads in COMMON_PAYLOADS.items():
                for payload in payloads:
                    tests.append({
                        "endpoint": ep,
                        "vulnerability": vuln_type,
                        "payload": payload,
                    })
        return tests

    @staticmethod
    def fuzz_parameter(param: dict) -> list[Any]:
        param_type = param.get("schema", {}).get("type", "string")
        return list(PARAM_FUZZ_VALUES.get(param_type, ["FUZZ"]))

    def to_findings(self, analysis: OpenAPIAnalysis) -> list[Finding]:
        return list(analysis.findings)


def discover_specs(base_url: str, fetch_fn: Callable | None = None) -> list[str]:
    found: list[str] = []
    for path in COMMON_SPEC_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        if fetch_fn is None:
            found.append(url)
            continue
        try:
            resp = fetch_fn({"url": url, "method": "GET"})
            if not resp or resp.get("status_code") != 200:
                continue
            body = resp.get("body", "")
            if "openapi" in body[:500] or "swagger" in body[:500]:
                found.append(url)
        except Exception:
            continue
    return found

def get_spec_paths() -> list[str]:
    return list(COMMON_SPEC_PATHS)
