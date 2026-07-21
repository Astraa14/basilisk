"""Kubernetes manifest and container configuration vulnerability scanning."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

MANIFEST_FILES = [
    "*.yaml", "*.yml", "*.json",
    "Dockerfile", "Dockerfile.*",
    "docker-compose.yml", "docker-compose.yaml",
    "Chart.yaml", "values.yaml",
    "kustomization.yaml", "kustomization.yml",
    ".dockerignore",
]

PRIVILEGED_CHECKS = [
    {"check": "privileged: true", "severity": "Critical", "desc": "Container runs in privileged mode"},
    {"check": "allowPrivilegeEscalation: true", "severity": "High", "desc": "Privilege escalation allowed"},
    {"check": "runAsUser: 0", "severity": "High", "desc": "Container runs as root (UID 0)"},
    {"check": "readOnlyRootFilesystem: false", "severity": "Low", "desc": "Root filesystem is writable"},
    {"check": "hostNetwork: true", "severity": "High", "desc": "Host network namespace shared"},
    {"check": "hostPID: true", "severity": "Critical", "desc": "Host PID namespace shared"},
    {"check": "hostIPC: true", "severity": "High", "desc": "Host IPC namespace shared"},
    {"check": 'capabilities:\n        add:', "severity": "Medium", "desc": "Extra Linux capabilities added"},
]

INSECURE_PATTERNS = [
    {"pattern": r"image:\s+.*:latest", "severity": "Medium", "desc": "Using 'latest' image tag"},
    {"pattern": r"imagePullPolicy:\s*(IfNotPresent|Never)", "severity": "Low", "desc": "Not always pulling fresh images"},
    {"pattern": r"ports:\s*\n\s+-.*:.*", "severity": "Medium", "desc": "NodePort service exposes port externally"},
    {"pattern": r"serviceAccountName:\s*default", "severity": "Low", "desc": "Using default service account"},
    {"pattern": r"securityContext:\s*\n\s+runAsNonRoot:\s*false", "severity": "High", "desc": "runAsNonRoot disabled"},
    {"pattern": r"resources:\s*\n\s+limits:", "severity": "Info", "desc": "Resource limits defined (good practice)"},
]

DOCKERFILE_BEST_PRACTICES = [
    {"pattern": r"FROM\s+\w+:\s*latest", "severity": "Medium", "desc": "Using 'latest' base image"},
    {"pattern": r"USER\s+root", "severity": "High", "desc": "Dockerfile uses root user"},
    {"pattern": r"ADD\s+https?://", "severity": "Medium", "desc": "ADD with remote URL (prefer curl/wget)"},
    {"pattern": r"RUN\s+apt-get\s+upgrade", "severity": "Low", "desc": "apt-get upgrade without pinning"},
    {"pattern": r"EXPOSE\s+22", "severity": "High", "desc": "SSH port exposed in container"},
    {"pattern": r"ENV\s+(PASSWORD|SECRET|KEY|TOKEN)=", "severity": "Critical", "desc": "Secret in environment variable"},
    {"pattern": r"COPY\s+(\.env|credentials\.json|secrets\.yml)", "severity": "Critical", "desc": "Credentials copied into image"},
]


@dataclass
class K8sVuln:
    resource: str
    kind: str
    severity: str
    description: str
    line_number: int = 0


@dataclass
class K8sScanResult:
    total_manifests: int = 0
    vulnerabilities: list[K8sVuln] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class K8sScanner:
    """Scan Kubernetes manifests and Dockerfiles for security issues."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.result = K8sScanResult()

    def scan(self) -> K8sScanResult:
        if self.path.is_file():
            self._scan_file(self.path)
        elif self.path.is_dir():
            for pattern in ["**/*.yaml", "**/*.yml", "**/Dockerfile*", "**/docker-compose*"]:
                for f in sorted(self.path.glob(pattern)):
                    if any(ignored in f.name.lower() for ignored in ["node_modules", ".git", "venv"]):
                        continue
                    self._scan_file(f)
        self._findings_from_vulns()
        return self.result

    def _scan_file(self, filepath: Path) -> None:
        self.result.total_manifests += 1
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.debug("Cannot read %s: %s", filepath, e)
            return

        if filepath.name.startswith("Dockerfile") or filepath.suffix == "" and "Dockerfile" in filepath.name:
            self._scan_dockerfile(filepath, content)
        elif filepath.suffix in (".yaml", ".yml"):
            self._scan_yaml(filepath, content)
            self._scan_yaml_for_k8s(filepath, content)

    def _scan_dockerfile(self, filepath: Path, content: str) -> None:
        for i, line in enumerate(content.splitlines(), 1):
            for check in DOCKERFILE_BEST_PRACTICES:
                if re.search(check["pattern"], line, re.I):
                    self.result.vulnerabilities.append(K8sVuln(
                        resource=str(filepath),
                        kind="Dockerfile",
                        severity=check["severity"],
                        description=check["desc"],
                        line_number=i,
                    ))

    def _scan_yaml(self, filepath: Path, content: str) -> None:
        try:
            docs = list(yield_safe_load_all(content))
        except Exception:
            return

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", filepath.stem)
            resource_name = f"{kind}/{name}"

            if kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"):
                spec = doc.get("spec", {})
                if kind != "Pod":
                    spec = spec.get("template", {}).get("spec", spec)

                containers = spec.get("containers", []) + spec.get("initContainers", [])
                for container in containers:
                    self._check_container_security(resource_name, container)
                    self._check_container_resources(resource_name, container)

                self._check_pod_security(resource_name, spec)
                self._check_network_policy(doc)

    def _scan_yaml_for_k8s(self, filepath: Path, content: str) -> None:
        for check in PRIVILEGED_CHECKS:
            if check["check"] in content:
                self.result.vulnerabilities.append(K8sVuln(
                    resource=str(filepath),
                    kind="Kubernetes",
                    severity=check["severity"],
                    description=check["desc"],
                ))

        for check in INSECURE_PATTERNS:
            if re.search(check["pattern"], content, re.MULTILINE):
                self.result.vulnerabilities.append(K8sVuln(
                    resource=str(filepath),
                    kind="Kubernetes",
                    severity=check["severity"],
                    description=check["desc"],
                ))

    def _check_container_security(self, resource: str, container: dict) -> None:
        sec = container.get("securityContext", {})
        if sec.get("privileged"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "Critical", "Privileged container"))
        if sec.get("allowPrivilegeEscalation"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "High", "Privilege escalation allowed"))
        if sec.get("runAsUser") == 0:
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "High", "Container runs as root"))
        if not sec.get("readOnlyRootFilesystem"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "Low", "Writable root filesystem"))

    def _check_container_resources(self, resource: str, container: dict) -> None:
        resources = container.get("resources", {})
        if not resources.get("limits") and not resources.get("requests"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "Medium", "No resource limits/requests"))

    def _check_pod_security(self, resource: str, spec: dict) -> None:
        if spec.get("hostNetwork"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "High", "Host network shared"))
        if spec.get("hostPID"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "Critical", "Host PID namespace"))
        if spec.get("hostIPC"):
            self.result.vulnerabilities.append(K8sVuln(resource, "Pod", "High", "Host IPC namespace"))

    def _check_network_policy(self, doc: dict) -> None:
        kind = doc.get("kind", "")
        if kind == "Namespace":
            name = doc.get("metadata", {}).get("name", "")
            self.result.vulnerabilities.append(K8sVuln(
                f"Namespace/{name}", "Namespace", "Info",
                f"Namespace '{name}' defined — ensure NetworkPolicy exists",
            ))

    def _findings_from_vulns(self) -> None:
        for v in self.result.vulnerabilities:
            cvss, vector = score_finding("container_escape")
            self.result.findings.append(
                Finding(
                    vulnerability=f"K8s Security: {v.description}",
                    severity=v.severity,
                    description=f"Resource: {v.resource} — {v.description}",
                    target=v.resource,
                    attack_type="container_escape",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation=f"Fix '{v.description}' in {v.resource}. Refer to Kubernetes security best practices.",
                )
            )


def yield_safe_load_all(content: str):
    try:
        import yaml
        for doc in yaml.safe_load_all(content):
            if doc is not None:
                yield doc
    except ImportError:
        yield from _simple_yaml_split(content)
    except Exception:
        pass


def _simple_yaml_split(content: str):
    docs = re.split(r"\n---\n", content)
    import json as _json
    for doc_text in docs:
        try:
            import yaml as _yaml
            doc = _yaml.safe_load(doc_text)
            if doc:
                yield doc
        except Exception:
            pass


def scan_kubernetes(path: str | Path) -> K8sScanResult:
    scanner = K8sScanner(path)
    return scanner.scan()
