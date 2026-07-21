"""Advanced GraphQL security analysis — introspection abuse, complexity, batching."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from basilisk.models import Finding
from basilisk.scoring import score_finding

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphql/v1", "/api/graphql", "/gql",
    "/query", "/v1/graphql", "/graph", "/api/v1/graphql",
    "/graphql/explorer", "/playground",
]

COMPLEXITY_QUERIES = [
    {"name": "Deeply nested", "query": "{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r{s{t{u{v{w{x{y{z{a{b{c{d{e{f{g{h{i{j{k{}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"},
    {"name": "Alias abuse", "query": "query{" + ",".join([f"a{i}:__typename" for i in range(50)]) + "}"},
    {"name": "Directive abuse", "query": "{__typename @skip(if:false) @include(if:true)}"},
    {"name": "Fragment explosion", "query": "fragment A on Query{a,b,c}A"},
    {"name": "Circular fragment", "query": "fragment A on Query{...B}fragment B on Query{...A}"},
]

INTROSPECTION_QUERIES = [
    {"name": "Full schema", "query": "{__schema{types{name,fields{name,type{name,kind}}}}}"},
    {"name": "Type enumeration", "query": "{__schema{types{name}}}"},
    {"name": "Query type", "query": "{__schema{queryType{name,mutationType{name}}}}"},
    {"name": "Directives", "query": "{__schema{directives{name,locations}}}"},
]

DOS_PAYLOADS = [
    {"name": "Array batching", "payload": json.dumps([{"query": "{__typename}"}] * 200)},
    {"name": "Field duplication", "query": "{" + "a:__typename," * 200 + "__typename}"},
    {"name": "Oversized string", "query": "{__typename}", "variables": {"x": "A" * 50000}},
]


@dataclass
class GraphQLAnalysis:
    introspection_enabled: bool = False
    endpoint_found: str = ""
    depth_score: int = 0
    complexity_score: int = 0
    batch_accepted: bool = False
    has_directives: bool = False
    field_suggestions: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class GraphQLAdvancedAnalyzer:
    """Deep GraphQL security analysis — complexity attacks and introspection."""

    def __init__(self, fetch_fn: Callable | None = None):
        self.fetch_fn = fetch_fn

    def analyze(self, base_url: str) -> GraphQLAnalysis:
        result = GraphQLAnalysis()
        if not self.fetch_fn:
            return result

        endpoint = self._discover_endpoint(base_url)
        if not endpoint:
            return result

        result.endpoint_found = endpoint
        self._test_introspection(endpoint, result)
        self._test_complexity(endpoint, result)
        self._test_dos(endpoint, result)

        return result

    def _discover_endpoint(self, base_url: str) -> str | None:
        for ep in GRAPHQL_ENDPOINTS:
            url = f"{base_url.rstrip('/')}{ep}"
            try:
                resp = self.fetch_fn({
                    "url": url,
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"query": "{__typename}"}),
                })
                if resp and resp.get("status_code") in (200, 400):
                    body = resp.get("body", "")
                    if "data" in body or "errors" in body or "__typename" in body:
                        return url
            except Exception:
                continue

            try:
                resp = self.fetch_fn({"url": url, "method": "GET"})
                if resp and resp.get("status_code") == 200:
                    body = resp.get("body", "")
                    if "graphql" in body.lower() or "playground" in body.lower():
                        return url
            except Exception:
                continue

        return base_url.rstrip("/") + "/graphql" if "graphql" not in base_url else base_url

    def _test_introspection(self, endpoint: str, result: GraphQLAnalysis) -> None:
        for test in INTROSPECTION_QUERIES:
            resp = self._gql(endpoint, test["query"])
            if not resp:
                continue
            body = resp.get("body", "")
            try:
                data = json.loads(body)
                if "data" in data and isinstance(data["data"], dict):
                    inner = data["data"]
                    if "__schema" in inner or "__type" in inner:
                        result.introspection_enabled = True
                        cvss, vector = score_finding("graphql")
                        result.findings.append(
                            Finding(
                                vulnerability="GraphQL Introspection Enabled (Advanced)",
                                severity="Medium",
                                description=f"Full introspection via {test['name']}. Schema can be extracted entirely.",
                                target=endpoint,
                                attack_type="graphql",
                                payload=test["query"][:80],
                                cvss_score=cvss,
                                cvss_vector=vector,
                                remediation="Disable introspection in production environments.",
                            )
                        )
                        break
            except (json.JSONDecodeError, TypeError):
                pass

    def _test_complexity(self, endpoint: str, result: GraphQLAnalysis) -> None:
        for test in COMPLEXITY_QUERIES[:3]:
            query = test.get("query", "")
            if not query:
                continue
            resp = self._gql(endpoint, query)
            if not resp:
                continue

            elapsed = resp.get("elapsed_time", 0)
            status = resp.get("status_code", 0)
            body = resp.get("body", "")

            result.complexity_score = max(result.complexity_score, len(query) // 100)
            result.depth_score = max(result.depth_score, query.count("{"))

            if status == 200 and len(body) > 100:
                cvss, vector = score_finding("graphql")
                result.findings.append(
                    Finding(
                        vulnerability=f"GraphQL Complexity Vector: {test['name']}",
                        severity="Medium",
                        description=f"Complex query '{test['name']}' accepted (HTTP 200). Potential DoS vector. Response: {len(body)} bytes.",
                        target=endpoint,
                        attack_type="graphql",
                        payload=test["query"][:60],
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Implement query complexity analysis, depth limiting, and rate limiting.",
                    )
                )

            if elapsed > 3.0:
                cvss, vector = score_finding("graphql")
                result.findings.append(
                    Finding(
                        vulnerability="GraphQL Slow Query (DoS Risk)",
                        severity="Medium",
                        description=f"Complex query took {elapsed:.1f}s. Potential DoS via resource exhaustion.",
                        target=endpoint,
                        attack_type="graphql",
                        payload=test["query"][:60],
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Set query timeouts and implement query complexity scoring.",
                    )
                )

    def _test_dos(self, endpoint: str, result: GraphQLAnalysis) -> None:
        for test in DOS_PAYLOADS:
            payload_data: dict = {}
            data: str | dict = test.get("payload", test.get("query", ""))
            if isinstance(data, str) and data.startswith("["):
                result.batch_accepted = True
                cvss, vector = score_finding("graphql")
                result.findings.append(
                    Finding(
                        vulnerability="GraphQL Batch Abuse Possible",
                        severity="High",
                        description="Server accepts batched GraphQL queries. Potential for batch-based DoS or brute force.",
                        target=endpoint,
                        attack_type="graphql",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Limit batch query size and implement query rate limiting.",
                    )
                )
                return

    def _gql(self, endpoint: str, query: str) -> dict | None:
        if not self.fetch_fn:
            return None
        return self.fetch_fn({
            "url": endpoint,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"query": query}),
        })

    def extract_schema(self, endpoint: str) -> str | None:
        query = INTROSPECTION_QUERIES[0]["query"]
        resp = self._gql(endpoint, query)
        if not resp:
            return None
        try:
            data = json.loads(resp.get("body", "{}"))
            return json.dumps(data.get("data", {}), indent=2)[:5000]
        except (json.JSONDecodeError, TypeError):
            return None


def get_graphql_endpoints() -> list[str]:
    return list(GRAPHQL_ENDPOINTS)

def get_complexity_queries() -> list[dict]:
    return list(COMPLEXITY_QUERIES)
