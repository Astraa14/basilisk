"""BOLA (Broken Object Level Authorization) / IDOR detection for REST APIs."""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse, urljoin

from basilisk.models import Finding
from basilisk.scoring import score_finding


# Common resource ID patterns
ID_PATTERNS = [
    re.compile(r"/(\d+)(?:/|$)"),  # numeric IDs
    re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", re.I),  # UUIDs
    re.compile(r"/([0-9a-f]{24})(?:/|$)", re.I),  # MongoDB ObjectIDs
]

# ID swap values for testing
NUMERIC_SWAPS = ["1", "2", "0", "999999", "-1"]
UUID_SWAP = "00000000-0000-0000-0000-000000000001"
OBJECTID_SWAP = "000000000000000000000001"


def extract_resource_ids(url: str) -> list[dict]:
    """Find resource IDs in URL paths."""
    path = urlparse(url).path
    found: list[dict] = []

    for pattern in ID_PATTERNS:
        for match in pattern.finditer(path):
            found.append({
                "value": match.group(1),
                "start": match.start(1),
                "end": match.end(1),
                "type": _classify_id(match.group(1)),
            })

    return found


def _classify_id(value: str) -> str:
    if re.match(r"^\d+$", value):
        return "numeric"
    if re.match(r"^[0-9a-f]{8}-", value, re.I):
        return "uuid"
    if re.match(r"^[0-9a-f]{24}$", value, re.I):
        return "objectid"
    return "unknown"


def generate_swap_urls(url: str) -> list[dict]:
    """Generate URLs with swapped resource IDs for IDOR testing."""
    ids = extract_resource_ids(url)
    swap_urls: list[dict] = []

    for id_info in ids:
        original = id_info["value"]
        id_type = id_info["type"]

        if id_type == "numeric":
            swaps = [s for s in NUMERIC_SWAPS if s != original]
        elif id_type == "uuid":
            swaps = [UUID_SWAP] if UUID_SWAP != original else []
        elif id_type == "objectid":
            swaps = [OBJECTID_SWAP] if OBJECTID_SWAP != original else []
        else:
            swaps = ["1", "test"]

        for swap_val in swaps:
            path = urlparse(url).path
            new_path = path[:id_info["start"]] + swap_val + path[id_info["end"]:]
            parsed = urlparse(url)
            new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if parsed.query:
                new_url += f"?{parsed.query}"
            swap_urls.append({
                "url": new_url,
                "original_id": original,
                "swapped_id": swap_val,
                "id_type": id_type,
            })

    return swap_urls


def detect_bola(
    original_response: dict,
    swapped_response: dict,
    swap_info: dict,
) -> Finding | None:
    """
    Compare responses from original and swapped resource IDs.
    If the swapped ID returns another user's data, it's BOLA.
    """
    orig_status = original_response.get("status_code", 0)
    swap_status = swapped_response.get("status_code", 0)
    orig_body = original_response.get("body", "")
    swap_body = swapped_response.get("body", "")
    target = swap_info.get("url", "")

    # If swapped request returns 200 with different data, possible IDOR
    if swap_status == 200 and orig_status == 200:
        if swap_body != orig_body and len(swap_body) > 50:
            # Check if response contains structured data
            try:
                swap_data = json.loads(swap_body)
                if isinstance(swap_data, dict) and swap_data:
                    # Different object was returned — BOLA confirmed
                    cvss, vector = score_finding("bola")
                    return Finding(
                        vulnerability="Broken Object Level Authorization (BOLA/IDOR)",
                        severity="High",
                        description=(
                            f"Swapping resource ID from '{swap_info['original_id']}' to "
                            f"'{swap_info['swapped_id']}' returned different data "
                            f"({len(swap_body)} bytes). Unauthorized access to another object."
                        ),
                        target=target,
                        attack_type="bola",
                        payload=f"ID: {swap_info['original_id']} → {swap_info['swapped_id']}",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation="Implement object-level authorization checks in API endpoints.",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                    )
            except (json.JSONDecodeError, TypeError):
                pass

            # Non-JSON but different content
            if len(swap_body) > 100:
                cvss, vector = score_finding("bola")
                return Finding(
                    vulnerability="Potential BOLA/IDOR (Different Response)",
                    severity="Medium",
                    description=(
                        f"Swapping ID '{swap_info['original_id']}' → '{swap_info['swapped_id']}' "
                        f"returned different content ({len(swap_body)} bytes)."
                    ),
                    target=target,
                    attack_type="bola",
                    payload=f"ID: {swap_info['original_id']} → {swap_info['swapped_id']}",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    confidence=0.6,
                )

    # Swapped returns 200 when it should return 403/404
    if swap_status == 200 and swap_info["swapped_id"] in ("-1", "999999", "0"):
        if len(swap_body) > 50:
            cvss, vector = score_finding("bola")
            return Finding(
                vulnerability="Potential BOLA (Boundary ID Accessible)",
                severity="Medium",
                description=(
                    f"Edge-case ID '{swap_info['swapped_id']}' returned HTTP 200 with content. "
                    f"Expected 403/404 for unauthorized access."
                ),
                target=target,
                attack_type="bola",
                payload=f"ID: {swap_info['swapped_id']}",
                cvss_score=cvss,
                cvss_vector=vector,
                confidence=0.5,
            )

    return None
