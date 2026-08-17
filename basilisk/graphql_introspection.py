"""GraphQL introspection and schema analysis.

Supports querying a GraphQL endpoint's __schema and __type introspection
endpoints to discover types, fields, inputs, and enums. Results can be
used to generate targeted fuzzing queries against the API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

INTROSPECTION_QUERIES: dict[str, str] = {
    "schema": """
        query {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          name
          kind
          fields(includeDeprecated: false) {
            name
            description
            args {
              name
              description
              type { name kind ofType }
            }
            inputFields {
              name
              description
              type { name kind ofType }
            }
            enumValues {
              name
              description
              isDeprecated
            }
          }
          enumValues(includeDeprecated: false) {
            name
            description
            isDeprecated
          }
        }
    """,
    "type": """query ($name: String!) {
        __type(name: $name) {
          name
          kind
          fields(name: "") {
            name
            description
            args {
              name
              type { name kind ofType }
            }
          }
          inputFields {
            name
            type { name kind ofType }
          }
          enumValues {
            name
          }
        }
      }""",
    "inputs": """query {
        __introspectionQuery {
          __schema {
            types {
              name
              kind
              fields {
                name
                args {
                  name
                  defaultValue
                }
              }
            }
          }
        }
      }""",
}


def introspect(engine, url: str, timeout: float = 5.0) -> dict | None:
    """Run __schema introspection against a GraphQL endpoint.

    Returns the parsed introspection data, or None on failure.
    """
    import requests

    payload = {"query": INTROSPECTION_QUERIES["schema"]}
    try:
        response = engine.send("POST", url, json=payload, timeout=timeout)
        if not response:
            return None
        data = response.get("body", "")
        # GraphQL responses are JSON with a "data" key
        try:
            j = json.loads(data)
            if "errors" in j:
                logger.debug("GraphQL introspection errors: %s", j["errors"])
                return None
            return j.get("data", {})
        except json.JSONDecodeError:
            logger.debug("GraphQL introspection response not JSON: %s", data[:200])
            return None
    except Exception as exc:
        logger.debug("GraphQL introspection failed for %s: %s", url, exc)
        return None


def find_graphql_operations(introspection_data: dict) -> list[dict]:
    """Extract candidate operation names and shapes from introspection data.

    Returns a list of dicts with 'name', 'operationType', 'fields', 'inputs'.
    """
    if not introspection_data:
        return []
    types = introspection_data.get("__schema", {}).get("types", [])
    candidates: list[dict] = []
    for t in types:
        if t.get("kind") == "OBJECT":
            name = t.get("name", "")
            fields = t.get("fields", [])
            field_list: list[dict] = []
            args_list: list[dict] = []
            for f in fields:
                fn = f.get("name", "")
                fargs = f.get("args", [])
                arg_details: list[dict] = []
                for a in fargs:
                    at = a.get("type", {})
                    arg_details.append(
                        {"name": a.get("name", ""), "type": at.get("name", "")}
                    )
                fields_detail = {
                    "name": fn,
                    "description": f.get("description", ""),
                    "args": arg_details,
                }
                fields_detail["arg_types"] = [
                    a.get("type", {}).get("name", "") for a in f.get("args", [])
                ]
                fields_detail["arg_defaults"] = [
                    a.get("defaultValue", "") for a in f.get("args", [])
                ]
                fields_detail["inputFields"] = [
                    {"name": i.get("name", ""), "type": i.get("type", {}).get("name", "")}
                    for i in f.get("inputFields", [])
                ]
                fields_list.append(fields_detail)
            else:
                fields_list = []
            candidates.append(
                {
                    "name": name,
                    "operationType": "query",
                    "fields": fields_list,
                }
            )
    return candidates


def generate_fuzzing_queries(
    candidates: list[dict], max_depth: int = 2
) -> list[dict]:
    """Generate GraphQL fuzzing payloads from introspection candidates.

    Returns a list of operation dicts with method, url, json body.
    """
    results: list[dict] = []
    for cand in candidates:
        name = cand.get("name", "")
        fields = cand.get("fields", [])
        # Build a simple query exercising the type's fields
        field_strs: list[str] = []
        for f in fields[:5]:  # limit to first 5 fields
            fname = f.get("name", "")
            arg_strs: list[str] = []
            for arg in f.get("args", [])[:3]:
                arg_name = arg.get("name", "")
                arg_type = arg.get("type", "")
                # Use null for input types, random string for others
                arg_strs.append(f'{arg_name}: null')
            field_strs.append(f'  {fname}({", ".join(arg_strs)})')
        query = "{\n  " + " \n  ".join(field_strs) + "\n}"
        results.append(
            {
                "method": "POST",
                "url": "",
                "json_body": query,
                "attack_type": "graphql",
            }
        )
    return results