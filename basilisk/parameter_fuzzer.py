"""URL encoding, parameter handling, and HTTP parameter pollution detection.

Provides: custom encoding schemes, parameter ordering, duplicate parameter
detection (parameter pollution), and identification of parameter injection
vulnerabilities.
"""

from __future__ import annotations

import itertools
import logging
import re
from urllib.parse import quote, unquote, urlencode, parse_qsl
from typing import Any, Dict, List, Optional, Tuple

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

# Common encoding schemes
ENCODING_SCHEMES: dict[str, callable] = {
    "utf8": lambda s: quote(s, encoding="utf-8"),
    "percent": lambda s: quote(s, safe="/"),
    "double": lambda s: quote(quote(s, safe="/"), safe="/"),
    "hex": lambda s: "".join(f"%{b:02x}" for b in s.encode("utf-8")),
    "base64": lambda s: __import__("base64").b64encode(s.encode("utf-8")).decode(),
    "unicode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
}

# HTTP Parameter Pollution (HPP) vectors - pairs of parameters that cause
# backend discrepancy
HPP_VECTORS: dict[str, list[dict]] = {
    "clte": [
        {"param": "CL", "inject": "Content-Length", "effect": "Backend may use injected value"},
        {"param": "TE", "inject": "Transfer-Encoding", "effect": "Backend may ignore original"},
    ],
    "order": [
        {"param1": "sort", "param2": "order", "effect": "Backend may prioritize one over other"},
        {"param1": "page", "param2": "offset", "effect": "Off-by-one or skipping"},
    ],
}


def encode_parameter(
    value: str,
    scheme: str = "utf8",
    double_encode: bool = False,
) -> str:
    """Encode a parameter value using the specified scheme.

    Args:
        value: The parameter value to encode.
        scheme: Encoding scheme ("utf8", "percent", "double", "hex", "base64", "unicode").
        double_encode: Whether to double-encode the result.

    Returns:
        The encoded parameter value.
    """
    encoder = ENCODING_SCHEMES.get(scheme, ENCODING_SCHEMES["utf8"])
    encoded = encoder(value)
    if double_encode:
        encoded = encoder(encoded)
    return encoded


def build_parameter_pairs(
    base_params: dict[str, list[str]],
    pollution_vectors: dict[str, list[dict]] | None = None,
) -> list[dict[str, str]]:
    """Build parameter pollution test pairs from a base parameter dict.

    Args:
        base_params: Dict of parameter name to list of values.
        pollution_vectors: HPP vectors to apply.

    Returns:
        List of parameter dicts suitable for HTTP request bodies.
    """
    if pollution_vectors is None:
        pollution_vectors = HPP_VECTORS

    results: list[dict[str, str]] = []
    for vector_name, vector_list in pollution_vectors.items():
        for vector in vector_list:
            params = dict(base_params)
            # Add polluted parameter pairs
            p1_name = vector.get("param1", "")
            p2_name = vector.get("param2", "")
            p1_val = vector.get("inject", "")
            if p1_name and p1_name in params and params[p1_name]:
                params[p1_name] = p1_val or params[p1_name][0]
            if p2_name and p2_name in params and params[p2_name]:
                params[p2_name] = p1_val or params[p2_name][0]  # reuse injected value
            results.append(params)
    # Also return original params for baseline
    results.append(dict(base_params))
    return results


def detect_parameter_pollution(
    original_response: dict,
    modified_response: dict,
    params_tested: list[str],
) -> tuple[bool, list[str]]:
    """Detect HTTP Parameter Pollution between two responses.

    Args:
        original_response: Response dict from original request.
        modified_response: Response dict from polluted request.
        params_tested: List of parameter names that were modified.

    Returns:
        (is_pollution, evidence) tuple.
    """
    evidence: list[str] = []
    is_pollution = False

    orig_status = original_response.get("status_code")
    mod_status = modified_response.get("status_code")

    orig_body = original_response.get("body", "").lower()
    mod_body = modified_response.get("body", "").lower()

    # Status code difference
    if orig_status != mod_status:
        is_pollution = True
        evidence.append(
            f"Status code changed from {orig_status} to {mod_status} "
            f"when manipulating parameters: {params_tested}"
        )

    # Body content difference (significant change)
    # Strip simple variations
    orig_body_stripped = re.sub(r"\s+", " ", orig_body).strip()
    mod_body_stripped = re.sub(r"\s+", " ", mod_body).strip()
    if orig_body_stripped != mod_body_stripped:
        is_pollution = True
        evidence.append(
            f"Response body changed when manipulating parameters: {params_tested}"
        )

    # Header differences
    orig_headers = original_response.get("headers", {})
    mod_headers = modified_response.get("headers", {})
    for key in set(list(orig_headers.keys()) + list(mod_headers.keys())):
        if orig_headers.get(key) != mod_headers.get(key):
            is_pollution = True
            evidence.append(
                f"Response header '{key}' changed: "
                f"{orig_headers.get(key)} -> {mod_headers.get(key)}"
            )

    return is_pollution, evidence


def test_encoding_variants(
    engine,
    url: str,
    param_name: str,
    values: list[str],
    timeout: float = 5.0,
) -> list[Finding]:
    """Test a parameter with various encoding schemes and return findings.

    Args:
        engine: RequestEngine instance.
        url: Target URL with the parameter.
        param_name: Name of the parameter to fuzz.
        values: List of parameter values to test.
        timeout: Request timeout.

    Returns:
        List of Findings from encoding variations.
    """
    from basilisk.http import RequestEngine

    findings: list[Finding] = []
    parsed = url.split("?")[0] if "?" in url else url
    base_url = f"{parsed}?"

    for scheme in ENCODING_SCHEMES:
        for value in values:
            encoded_val = encode_parameter(value, scheme=scheme)
            test_url = f"{base_url}{param_name}={encoded_val}"
            try:
                response = engine.send("GET", test_url, timeout=timeout)
                if not response:
                    continue
                # Check for errors, unexpected behaviors
                status = response.get("status_code", 0)
                body = response.get("body", "") or ""
                # Heuristic: 5xx errors with certain encodings may indicate
                # backend confusion
                if 500 <= status <= 503:
                    findings.append(
                        Finding(
                            vulnerability=f"Parameter encoding '{scheme}' caused 5xx error",
                            severity="Medium",
                            description=f"Parameter '{param_name}' encoded as '{scheme}' "
                            f"value '{value}' caused server error {status}",
                            target=test_url,
                            attack_type="httppol",
                            cvss_score=score_finding("httppol")[0],
                            cvss_vector=score_finding("httppol")[1],
                            remediation=f"Validate and sanitize all input encodings server-side.",
                        )
                    )
                # Heuristic: 2xx with changed behavior
                elif 200 <= status <= 299 and "error" in body.lower():
                    findings.append(
                        Finding(
                            vulnerability=f"Parameter encoding '{scheme}' revealed error in response",
                            severity="Low",
                            description=f"Parameter '{param_name}' encoded as '{scheme}' "
                            f"value '{value}' revealed server error in response",
                            target=test_url,
                            attack_type="httppol",
                            cvss_score=score_finding("httppol")[0],
                            cvss_vector=score_finding("httppol")[1],
                            remediation=f"Sanitize parameter '{param_name}' before processing.",
                        )
                    )
            except Exception as exc:
                logger.debug("Encoding test failed for %s:%s: %s", param_name, scheme, exc)
    return findings