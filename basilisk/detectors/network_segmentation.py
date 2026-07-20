"""Network segmentation testing — probe for internal network access and firewall bypass."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


INTERNAL_NETWORKS = [
    {"cidr": "127.0.0.1", "name": "localhost"},
    {"cidr": "10.0.0.1", "name": "RFC1918 /8"},
    {"cidr": "172.16.0.1", "name": "RFC1918 /12"},
    {"cidr": "192.168.1.1", "name": "RFC1918 /16"},
    {"cidr": "0.0.0.0", "name": "catch-all"},
    {"cidr": "::1", "name": "IPv6 localhost"},
    {"cidr": "169.254.169.254", "name": "Cloud metadata"},
    {"cidr": "metadata.google.internal", "name": "GCP metadata"},
]

SEGMENTATION_PAYLOADS = [
    f"http://{net['cidr']}:{port}"
    for net in INTERNAL_NETWORKS
    for port in [80, 443, 8080, 8443, 6379, 27017, 3306, 5432, 9200, 22]
]

INTERNAL_SERVICE_SIGNATURES = {
    "redis": ["redis", "+ok", "-err"],
    "mongodb": ["mongodb", "mongos"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql", "psql"],
    "elasticsearch": ["elasticsearch", "cluster_name"],
    "docker": ["docker", "container"],
    "kubernetes": ["kubernetes", "kube-system"],
    "dashboard": ["dashboard", "admin", "grafana"],
}


def detect_internal_access(response: dict, target_url: str) -> Finding | None:
    body = response.get("body", "")
    status = response.get("status_code", 0)
    headers = response.get("headers", {})
    lower_body = body.lower()

    if status in (200, 201, 202, 301, 302) and len(body) > 50:
        for service, sigs in INTERNAL_SERVICE_SIGNATURES.items():
            if any(sig in lower_body for sig in sigs):
                cvss, vector = score_finding("network_segmentation")
                return Finding(
                    vulnerability="Internal Network Access via SSRF",
                    severity="Critical",
                    description=f"Successfully accessed internal service '{service}' at {target_url} (HTTP {status}). Internal network segmentation bypassed.",
                    target=target_url,
                    attack_type="network_segmentation",
                    payload=target_url[:80],
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Implement proper network segmentation. Use firewalls to block outbound traffic to internal networks from web-facing services.",
                )

        cvss, vector = score_finding("network_segmentation")
        return Finding(
            vulnerability="Potential Internal Network Access",
            severity="High",
            description=f"Internal URL {target_url} returned HTTP {status} with {len(body)} bytes. Possible network segmentation bypass.",
            target=target_url,
            attack_type="network_segmentation",
            payload=target_url[:80],
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
            remediation="Implement proper network segmentation. Block outbound requests to internal IP ranges.",
        )

    return None


def get_payloads() -> list[dict]:
    return [{"url": payload} for payload in SEGMENTATION_PAYLOADS]
