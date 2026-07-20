"""Prototype pollution detection for JavaScript applications."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from basilisk.models import Finding
from basilisk.scoring import score_finding


PROTOTYPE_POLLUTION_PAYLOADS = [
    # JSON body payloads
    '{"__proto__": {"polluted": "yes"}}',
    '{"constructor": {"prototype": {"polluted": "yes"}}}',
    # Property assignment sequences (can be used in URLs or bodies depending on parser)
    '__proto__[polluted]=yes',
    '__proto__.polluted=yes',
    'constructor[prototype][polluted]=yes',
    'constructor.prototype.polluted=yes',
]

def generate_payloads(base_data: dict | None = None) -> list[str]:
    """Generate payload variations. If base_data is JSON, merge pollution vectors."""
    payloads = list(PROTOTYPE_POLLUTION_PAYLOADS)
    
    if base_data:
        try:
            # Create a JSON variant with the base data
            mutated1 = dict(base_data)
            mutated1["__proto__"] = {"polluted": "yes"}
            payloads.append(json.dumps(mutated1))
            
            mutated2 = dict(base_data)
            mutated2["constructor"] = {"prototype": {"polluted": "yes"}}
            payloads.append(json.dumps(mutated2))
        except Exception:
            pass
            
    return payloads


def detect_prototype_pollution(response: dict, payload: str) -> Finding | None:
    """Check if the payload successfully polluted an object."""
    body = response.get("body", "")
    target = response.get("url", "")
    
    # Check if the injected property is reflected in a way that suggests it was added to the object prototype
    # This is a heuristic. A true test requires a secondary request to see if the property persists globally,
    # or relying on application errors.
    
    # 1. Look for reflection of the polluted property in JSON responses
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            # If the application echoes back the object and it includes our polluted property
            if data.get("polluted") == "yes":
                cvss, vector = score_finding("prototype_pollution")
                return Finding(
                    vulnerability="Prototype Pollution",
                    severity="High",
                    description=f"Object property 'polluted' reflected in response. Payload: {payload[:60]}",
                    target=target,
                    attack_type="prototype_pollution",
                    payload=payload,
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Use Object.create(null) for dictionaries, or freeze/seal prototypes.",
                )
    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Look for specific JS errors that might indicate interference with object prototypes
    error_signatures = [
        "cannot convert object to primitive value",
        "maximum call stack size exceeded",
        "is not a function", # Might happen if we overwrite a built-in method
    ]
    
    lower_body = body.lower()
    for sig in error_signatures:
        if sig in lower_body and "__proto__" in payload:
            cvss, vector = score_finding("prototype_pollution")
            return Finding(
                vulnerability="Potential Prototype Pollution",
                severity="Medium",
                description=f"JS error '{sig}' triggered by prototype payload: {payload[:60]}",
                target=target,
                attack_type="prototype_pollution",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                confidence=0.5,
            )
            
    return None
