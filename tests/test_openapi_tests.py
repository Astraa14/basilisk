"""Tests for OpenAPI security test generation."""

import json

from basilisk.openapi_tests import OpenAPITestGenerator, discover_specs


def test_parse_spec_inherits_root_security_for_mutating_endpoints():
    spec = {
        "openapi": "3.0.0",
        "security": [{"BearerAuth": []}],
        "paths": {
            "/users": {
                "post": {
                    "parameters": [{"name": "username", "in": "query"}],
                }
            }
        },
    }
    generator = OpenAPITestGenerator(
        fetch_fn=lambda request: {
            "status_code": 200,
            "body": json.dumps(spec),
        }
    )

    result = generator.discover_and_analyze("https://example.test")

    assert result.endpoints[0].security == [{"BearerAuth": []}]
    assert result.endpoints_without_auth == []
    assert result.findings == []


def test_parse_spec_respects_explicit_empty_operation_security():
    spec = {
        "openapi": "3.0.0",
        "security": [{"BearerAuth": []}],
        "paths": {
            "/users": {
                "post": {
                    "security": [],
                    "parameters": [{"name": "username", "in": "query"}],
                }
            }
        },
    }
    generator = OpenAPITestGenerator(
        fetch_fn=lambda request: {
            "status_code": 200,
            "body": json.dumps(spec),
        }
    )

    result = generator.discover_and_analyze("https://example.test")

    assert len(result.endpoints_without_auth) == 1
    assert result.findings[0].vulnerability == "Unauthenticated API Endpoint"


def test_discover_specs_uses_fetch_fn_to_return_only_existing_specs():
    def fetch(request):
        if request["url"] == "https://example.test/openapi.json":
            return {"status_code": 200, "body": '{"openapi":"3.0.0"}'}
        return {"status_code": 404, "body": ""}

    assert discover_specs("https://example.test", fetch) == [
        "https://example.test/openapi.json"
    ]
