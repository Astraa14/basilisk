"""Recursive dependency graph analysis for supply chain attack paths."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    name: str
    version: str = ""
    depth: int = 0
    dependencies: list["DependencyNode"] = field(default_factory=list)
    is_dev: bool = False
    has_vulnerability: bool = False
    known_cve: str = ""
    license_name: str = ""
    outdated: bool = False


@dataclass
class DependencyGraph:
    root: str = ""
    nodes: list[DependencyNode] = field(default_factory=list)
    total_count: int = 0
    vulnerable_count: int = 0
    outdated_count: int = 0
    circular_deps: list[list[str]] = field(default_factory=list)


KNOWN_VULN_PACKAGES: dict[str, list[dict]] = {
    "npm": [
        {"name": "lodash", "versions_before": "4.17.21", "cve": "CVE-2021-23337"},
        {"name": "minimist", "versions_before": "1.2.6", "cve": "CVE-2021-44906"},
        {"name": "node-fetch", "versions_before": "2.6.7", "cve": "CVE-2022-0235"},
        {"name": "json5", "versions_before": "2.2.2", "cve": "CVE-2022-46175"},
        {"name": "path-parse", "versions_before": "1.0.7", "cve": "CVE-2021-23343"},
        {"name": "ansi-html", "versions_before": "0.0.8", "cve": "CVE-2021-23424"},
        {"name": "tmpl", "versions_before": "1.0.5", "cve": "CVE-2021-37284"},
        {"name": "nth-check", "versions_before": "2.0.1", "cve": "CVE-2021-37284"},
        {"name": "postcss", "versions_before": "8.4.31", "cve": "CVE-2023-44270"},
        {"name": "axios", "versions_before": "1.6.0", "cve": "CVE-2023-45857"},
    ],
    "pip": [
        {"name": "requests", "versions_before": "2.31.0", "cve": "CVE-2023-32681"},
        {"name": "urllib3", "versions_before": "1.26.18", "cve": "CVE-2023-45803"},
        {"name": "cryptography", "versions_before": "41.0.6", "cve": "CVE-2023-49084"},
        {"name": "jinja2", "versions_before": "3.1.3", "cve": "CVE-2024-22195"},
        {"name": "pillow", "versions_before": "10.2.0", "cve": "CVE-2023-50447"},
        {"name": "django", "versions_before": "5.0.3", "cve": "CVE-2024-27351"},
        {"name": "flask", "versions_before": "3.0.1", "cve": "CVE-2023-51441"},
        {"name": "certifi", "versions_before": "2024.2.2", "cve": "CVE-2023-37920"},
    ],
}


class DependencyAnalyzer:
    """Analyze project dependencies for vulnerable packages and supply chain risks."""

    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path)
        self.graph = DependencyGraph(root=str(self.project_path))
        self._visited: set[str] = set()

    def analyze(self) -> DependencyGraph:
        self._scan_package_json()
        self._scan_requirements_txt()
        self._scan_package_lock()
        self._scan_pdm_lock()
        self._detect_circular()
        self.graph.total_count = len(self.graph.nodes)
        return self.graph

    def _scan_package_json(self) -> None:
        pkg_json = self.project_path / "package.json"
        if not pkg_json.exists():
            return
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, version in deps.items():
                version_str = str(version).lstrip("^~>=<")
                is_dev = name in data.get("devDependencies", {})
                node = self._check_package("npm", name, version_str, is_dev)
                self.graph.nodes.append(node)

            yarn_path = self.project_path / "yarn.lock"
            if yarn_path.exists():
                self._parse_yarn_lock(yarn_path)

        except Exception as e:
            logger.debug("Failed to scan package.json: %s", e)

    def _scan_requirements_txt(self) -> None:
        req_path = self.project_path / "requirements.txt"
        if not req_path.exists():
            alt = self.project_path / "requirements"
            if alt.exists() and alt.is_dir():
                for f in sorted(alt.iterdir()):
                    if f.suffix == ".txt":
                        self._parse_requirements(f)
            return
        self._parse_requirements(req_path)

    def _parse_requirements(self, path: Path) -> None:
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", "git", "http")):
                    continue
                match = re.match(r"([a-zA-Z0-9_.-]+)\s*[><=!~]+\s*([\d.]+)", line)
                if match:
                    node = self._check_package("pip", match.group(1), match.group(2))
                    self.graph.nodes.append(node)
        except Exception as e:
            logger.debug("Failed to parse requirements: %s", e)

    def _scan_package_lock(self) -> None:
        lock_path = self.project_path / "package-lock.json"
        if lock_path.exists():
            self._parse_npm_lock(lock_path)

    def _parse_npm_lock(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            packages = data.get("packages", {})
            for pkg_path, info in packages.items():
                if pkg_path == "":
                    continue
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path.lstrip("/")
                version = str(info.get("version", ""))
                if name and version:
                    node = self._check_package("npm", name, version)
                    self.graph.nodes.append(node)
        except Exception as e:
            logger.debug("Failed to parse package-lock.json: %s", e)

    def _parse_yarn_lock(self, path: Path) -> None:
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = re.match(r'^\s{2}"?([\w@/-]+)@.*:$', line)
                if match:
                    name = match.group(1)
                    node = DependencyNode(name=name, depth=1)
                    self.graph.nodes.append(node)
        except Exception as e:
            logger.debug("Failed to parse yarn.lock: %s", e)

    def _scan_pdm_lock(self) -> None:
        pdm_path = self.project_path / "pdm.lock"
        if not pdm_path.exists():
            return
        try:
            data = json.loads(pdm_path.read_text(encoding="utf-8", errors="ignore"))
            for pkg in data.get("package", []):
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    node = self._check_package("pip", name, version)
                    self.graph.nodes.append(node)
        except Exception as e:
            logger.debug("Failed to parse pdm.lock: %s", e)

    def _check_package(self, ecosystem: str, name: str, version: str, is_dev: bool = False) -> DependencyNode:
        node = DependencyNode(name=name, version=version, is_dev=is_dev)
        vulns = KNOWN_VULN_PACKAGES.get(ecosystem, [])
        for v in vulns:
            if v["name"].lower() == name.lower():
                if self._version_less_than(version, v["versions_before"]):
                    node.has_vulnerability = True
                    node.known_cve = v["cve"]
                    self.graph.vulnerable_count += 1
                break
        return node

    def _version_less_than(self, v1: str, v2: str) -> bool:
        try:
            parts1 = [int(x) for x in re.split(r"[.\-_]", v1) if x.isdigit()]
            parts2 = [int(x) for x in re.split(r"[.\-_]", v2) if x.isdigit()]
            for a, b in zip(parts1, parts2):
                if a != b:
                    return a < b
            return len(parts1) < len(parts2)
        except (ValueError, TypeError):
            return False

    def _detect_circular(self) -> None:
        adj: dict[str, list[str]] = {}
        for node in self.graph.nodes:
            adj.setdefault(node.name, [])
            for dep in node.dependencies:
                adj.setdefault(node.name, []).append(dep.name)

        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(n: str) -> None:
            visited.add(n)
            rec_stack.add(n)
            path.append(n)
            for neighbor in adj.get(n, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    cycle = path[path.index(neighbor):] + [neighbor]
                    self.graph.circular_deps.append(cycle)
            path.pop()
            rec_stack.discard(n)

        for n in adj:
            if n not in visited:
                dfs(n)

    def to_findings(self, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen_cves: set[str] = set()
        for node in self.graph.nodes:
            if node.has_vulnerability and node.known_cve not in seen_cves:
                seen_cves.add(node.known_cve)
                cvss, vector = score_finding("dependency_check")
                findings.append(
                    Finding(
                        vulnerability=f"Supply Chain: {node.name} (CVE)",
                        severity="High",
                        description=f"{node.name}@{node.version} has known CVE: {node.known_cve}. Update to patched version.",
                        target=target,
                        attack_type="dependency_check",
                        payload=f"{node.name}=={node.version}",
                        cvss_score=cvss,
                        cvss_vector=vector,
                        remediation=f"Upgrade {node.name} to version {self._get_fixed_version(node.name)} or later.",
                    )
                )
        if self.graph.circular_deps:
            cvss, vector = score_finding("dependency_check")
            findings.append(
                Finding(
                    vulnerability="Supply Chain: Circular Dependencies",
                    severity="Low",
                    description=f"Found {len(self.graph.circular_deps)} circular dependency chain(s): {self.graph.circular_deps[0]}",
                    target=target,
                    attack_type="dependency_check",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation="Refactor dependencies to eliminate circular references.",
                )
            )
        return findings

    def _get_fixed_version(self, name: str) -> str:
        for eco in KNOWN_VULN_PACKAGES.values():
            for v in eco:
                if v["name"].lower() == name.lower():
                    return v["versions_before"]
        return "latest"


def analyze_path(path: str | Path) -> DependencyGraph:
    analyzer = DependencyAnalyzer(path)
    return analyzer.analyze()
