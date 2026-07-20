"""Privilege escalation detection — horizontal and vertical access control testing."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


ESCALATION_SCENARIOS: list[dict] = [
    {"name": "role_param", "description": "Role/user-type parameter manipulation"},
    {"name": "admin_path", "description": "Direct admin path access"},
    {"name": "id_switch", "description": "Switch user ID in request"},
    {"name": "method_bypass", "description": "HTTP method override for restricted actions"},
    {"name": "group_switch", "description": "Group/permission ID manipulation"},
]

ESCALATION_PAYLOADS = [
    {"header": "X-Role", "value": "admin"},
    {"header": "X-User-Role", "value": "administrator"},
    {"header": "X-Permissions", "value": "*"},
    {"header": "X-Access-Level", "value": "root"},
    {"param": "role", "value": "admin"},
    {"param": "user_type", "value": "administrator"},
    {"param": "group", "value": "admin"},
    {"param": "is_admin", "value": "true"},
    {"param": "admin", "value": "1"},
    {"method_override": "X-HTTP-Method-Override", "value": "DELETE"},
    {"method_override": "X-HTTP-Method-Override", "value": "PUT"},
]

ESCALATION_PATHS = [
    "/api/admin/users",
    "/api/users/1/role",
    "/admin/users",
    "/api/v1/users",
    "/internal/users",
]


def detect_escalation(
    response: dict,
    scenario_name: str,
    payload_desc: str,
    target: str = "",
) -> Finding | None:
    status = response.get("status_code", 0)
    body = response.get("body", "")

    if status in (200, 201, 202):
        cvss, vector = score_finding("privilege_escalation")
        return Finding(
            vulnerability=f"Privilege Escalation ({scenario_name})",
            severity="Critical",
            description=(
                f"Privilege escalation attempt '{scenario_name}' succeeded with "
                f"payload '{payload_desc}' (HTTP {status}). Unauthorized access to restricted functionality."
            ),
            target=target,
            attack_type="privilege_escalation",
            payload=payload_desc[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Implement proper role-based access control (RBAC) checks on all server-side endpoints.",
        )

    if status == 500:
        cvss, vector = score_finding("privilege_escalation")
        return Finding(
            vulnerability=f"Server Error on Escalation Attempt ({scenario_name})",
            severity="Medium",
            description=f"HTTP 500 when attempting privilege escalation: {payload_desc}",
            target=target,
            attack_type="privilege_escalation",
            payload=payload_desc[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.3,
            remediation="Handle authorization errors gracefully without exposing internal state.",
        )

    return None


def get_payloads() -> list[dict]:
    return list(ESCALATION_PAYLOADS)

def get_paths() -> list[str]:
    return list(ESCALATION_PATHS)

def get_scenarios() -> list[dict]:
    return list(ESCALATION_SCENARIOS)
