"""Business logic vulnerability detection — workflow bypass, negative numbers, etc."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


NEGATIVE_VALUES = ["-1", "-100", "-9999", "0"]
PRICE_MANIPULATION = [
    {"field": "price", "values": ["0", "-1", "0.01", "0.99"]},
    {"field": "quantity", "values": ["-1", "0", "99999"]},
    {"field": "discount", "values": ["100", "9999", "-1"]},
    {"field": "total", "values": ["0", "-1", "-100"]},
]

STEP_SKIP_SCENARIOS = [
    {"name": "checkout_without_cart", "path": "/api/checkout", "skip_headers": ["x-cart-id"]},
    {"name": "admin_without_auth", "path": "/api/admin", "skip_headers": ["authorization"]},
    {"name": "verify_skip", "path": "/api/verify", "skip_params": ["code"]},
]


def detect_price_manipulation(
    response: dict, field: str, value: str, target: str = ""
) -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)

    if status in (200, 201, 202):
        lower_body = body.lower()
        if "price" in lower_body or "total" in lower_body:
            cvss, vector = score_finding("business_logic")
            return Finding(
                vulnerability="Business Logic: Price Manipulation",
                severity="High",
                description=f"Field '{field}' accepted manipulated value '{value}' (HTTP {status}).",
                target=target,
                attack_type="business_logic",
                payload=f"{field}={value}",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Validate all price/total calculations server-side. Never trust client-side values.",
            )

    if status == 500:
        cvss, vector = score_finding("business_logic")
        return Finding(
            vulnerability="Business Logic: Server Error on Edge Value",
            severity="Medium",
            description=f"Server error (500) when submitting edge value '{value}' for field '{field}'.",
            target=target,
            attack_type="business_logic",
            payload=f"{field}={value}",
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
            remediation="Handle edge case values gracefully with proper validation.",
        )

    return None


def detect_step_skip(
    response: dict, scenario: dict, target: str = ""
) -> Finding | None:
    status = response.get("status_code", 0)
    body = response.get("body", "")

    if status in (200, 201, 202, 301, 302):
        cvss, vector = score_finding("business_logic")
        return Finding(
            vulnerability=f"Business Logic: {scenario['name']}",
            severity="Medium",
            description=f"Workflow step was bypassed: {scenario['name']} (HTTP {status}).",
            target=target,
            attack_type="business_logic",
            payload=f"bypass={scenario['name']}",
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Implement proper state validation and enforce workflow ordering server-side.",
        )

    return None


def get_price_tests() -> list[dict]:
    return list(PRICE_MANIPULATION)

def get_step_scenarios() -> list[dict]:
    return list(STEP_SKIP_SCENARIOS)
