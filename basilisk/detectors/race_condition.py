"""Race condition detection via concurrent request bursts."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


RACE_SCENARIOS = [
    {"name": "password_change", "description": "Concurrent password change requests"},
    {"name": "money_transfer", "description": "Concurrent fund transfer requests"},
    {"name": "cart_checkout", "description": "Concurrent checkout submissions"},
    {"name": "coupon_apply", "description": "Concurrent coupon redemptions"},
    {"name": "rate_limit_bypass", "description": "Burst requests to bypass rate limits"},
    {"name": "signup_bonus", "description": "Concurrent signup bonus claims"},
]


def detect_race_condition(
    responses: list[dict],
    scenario_name: str = "generic",
    target: str = "",
) -> Finding | None:
    if not responses or len(responses) < 2:
        return None

    success_count = sum(
        1 for r in responses if r.get("status_code", 0) in (200, 201, 202)
    )

    if success_count >= len(responses) - 1:
        for r in responses:
            body = r.get("body", "")
            status = r.get("status_code", 0)
            if status == 200 and ("success" in body.lower() or "ok" in body.lower()):
                cvss, vector = score_finding("race_condition")
                return Finding(
                    vulnerability=f"Race Condition ({scenario_name})",
                    severity="High",
                    description=(
                        f"All {len(responses)} concurrent requests succeeded. "
                        f"Potential race condition in '{scenario_name}' scenario."
                    ),
                    target=target,
                    attack_type="race_condition",
                    payload=f"burst={len(responses)}",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Use atomic database transactions and optimistic locking for concurrent operations.",
                )

    return None


def get_scenarios() -> list[dict]:
    return list(RACE_SCENARIOS)
