"""Blind SSRF detection using Out-Of-Band (OOB) channels."""

from __future__ import annotations

import uuid

from basilisk.models import Finding
from basilisk.scoring import score_finding

# In a real environment, this would integrate with a service like Interactsh or Burp Collaborator.
# For this implementation, we will use a hypothetical OOB domain and generate unique IDs.

OOB_DOMAIN = "oob.basilisk-scanner.local" # Placeholder

def generate_oob_payloads() -> tuple[list[str], str]:
    """Generate SSRF payloads pointing to a unique OOB domain."""
    unique_id = uuid.uuid4().hex[:8]
    callback_host = f"{unique_id}.{OOB_DOMAIN}"
    
    payloads = [
        f"http://{callback_host}",
        f"https://{callback_host}",
        f"//{callback_host}",
        f"file://{callback_host}/test",
        f"dict://{callback_host}:11111/",
        f"gopher://{callback_host}:22222/_test",
    ]
    return payloads, unique_id


def check_oob_interaction(unique_id: str) -> bool:
    """
    Check if the OOB service received an interaction for the unique_id.
    This is a mock implementation. In reality, it would poll the OOB provider's API.
    """
    # Mock: always returns False unless testing framework forces it
    # True implementation would HTTP GET from OOB provider API using unique_id
    return False 


def detect_ssrf_oob(response: dict, payload: str, unique_id: str) -> Finding | None:
    """
    Detect blind SSRF by checking for interactions with the OOB domain.
    Normally called asynchronously or after a delay.
    """
    target = response.get("url", "")
    
    interaction = check_oob_interaction(unique_id)
    
    if interaction:
        cvss, vector = score_finding("ssrf_oob")
        return Finding(
            vulnerability="Blind SSRF (Out-of-Band)",
            severity="Critical",
            description=f"Out-of-band network interaction detected for payload: {payload}",
            target=target,
            attack_type="ssrf_oob",
            payload=payload,
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Restrict outbound network access from the server, validate and sanitize all URLs.",
        )
        
    return None
