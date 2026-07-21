"""Serverless function vulnerability scanning — AWS Lambda, Google Cloud Functions, etc."""

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

SERVERLESS_FILE_PATTERNS = [
    "serverless.yml", "serverless.yaml",
    "template.yml", "template.yaml",  # SAM
    "function.json",  # GCF
    "app.yaml",  # AppEngine / GCF
    "index.py", "lambda_function.py",
    "handler.py", "handler.js", "index.js",
    "requirements.txt", "package.json",
]

AWS_LAMBDA_CHECKS = [
    {"check": r"environment:\s*\n\s+VARIABLES:\s*\n", "severity": "High", "desc": "Lambda env vars without KMS encryption"},
    {"check": r"Policies:\s*-\s*\n\s+Version:\s*'?\d+'?\s*\n\s+Statement:\s*\n\s+-\s*\n\s+Effect:\s*Allow\s*\n\s+Action:\s*\n\s+-\s*['\"]\*['\"]", "severity": "Critical", "desc": "IAM policy with wildcard (*) Action"},
    {"check": r"timeout:\s*[6-9]\d", "severity": "Low", "desc": "Lambda timeout > 60 seconds"},
    {"check": r"memorySize:\s*[3-9]\d{2,}", "severity": "Low", "desc": "Lambda memory > 300MB (cost)"},
    {"check": r"events:\s*\n\s+-\s*http:\s*\n\s+path:\s*/\w+\s*\n\s+method:\s*(GET|POST|PUT|DELETE)\s*\n\s+authorizer:", "severity": "Info", "desc": "Lambda with API Gateway authorizer (good)"},
]

GCF_CHECKS = [
    {"check": r"entryPoint:\s*\w+", "severity": "Info", "desc": "GCF entry point defined"},
    {"check": r"runtime:\s*(python|nodejs|go|java)", "severity": "Info", "desc": "GCF runtime specified"},
    {"check": r"environmentVariables:", "severity": "Medium", "desc": "GCF env vars defined"},
    {"check": r"ingressSettings:\s*ALLOW_ALL", "severity": "High", "desc": "GCF allows all ingress traffic"},
]

SENSITIVE_HANDLER_PATTERNS = [
    (r"os\.environ\s*\[", "Hardcoded env access", "Medium"),
    (r"boto3\.client|boto3\.resource", "AWS SDK usage", "Info"),
    (r"eval\(|exec\(", "Dynamic code execution", "Critical"),
    (r"subprocess\.(call|Popen|run)", "Shell execution", "High"),
    (r"__import__\(|importlib\.import_module", "Dynamic import", "Medium"),
    (r"json\.loads\(request\.body|json\.loads\(event", "JSON parsing", "Info"),
    (r"sqlite3\.connect|psycopg2\.connect|pymongo\.MongoClient", "DB connection in handler", "Medium"),
    (r"requests\.get\(|requests\.post\(", "Outbound HTTP from handler", "Info"),
]


@dataclass
class ServerlessFunction:
    name: str = ""
    runtime: str = ""
    timeout: int = 0
    memory: int = 0
    policies: list[str] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)
    handler_file: str = ""
    triggers: list[str] = field(default_factory=list)


@dataclass
class ServerlessScanResult:
    functions: list[ServerlessFunction] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class ServerlessScanner:
    """Scan serverless configurations and handler code for security issues."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.result = ServerlessScanResult()

    def scan(self) -> ServerlessScanResult:
        self._find_serverless_files(self.path)
        return self.result

    def _find_serverless_files(self, search_path: Path) -> None:
        for pattern in SERVERLESS_FILE_PATTERNS:
            for f in search_path.glob(f"**/{pattern}"):
                if "node_modules" in str(f) or ".git" in str(f) or "venv" in str(f):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    if f.name in ("serverless.yml", "serverless.yaml"):
                        self._check_serverless_yml(str(f), content)
                    elif f.name in ("template.yml", "template.yaml"):
                        self._check_sam_template(str(f), content)
                    elif f.name in ("requirements.txt", "package.json"):
                        self._check_handler_deps(str(f), content)
                    if f.suffix in (".py", ".js"):
                        self._check_handler_code(str(f), content)
                except Exception as e:
                    logger.debug("Error scanning %s: %s", f, e)

    def _check_serverless_yml(self, filepath: str, content: str) -> None:
        for check in AWS_LAMBDA_CHECKS:
            if re.search(check["check"], content, re.MULTILINE):
                self.result.vulnerabilities.append({
                    "file": filepath,
                    "severity": check["severity"],
                    "description": check["desc"],
                    "type": "Serverless Framework",
                })

        functions = re.findall(r"(\w+):\s*\n\s+handler:\s*(\S+)", content)
        for name, handler in functions:
            self.result.functions.append(ServerlessFunction(
                name=name, handler_file=handler,
            ))

    def _check_sam_template(self, filepath: str, content: str) -> None:
        for check in AWS_LAMBDA_CHECKS:
            if re.search(check["check"], content, re.MULTILINE):
                self.result.vulnerabilities.append({
                    "file": filepath,
                    "severity": check["severity"],
                    "description": check["desc"],
                    "type": "AWS SAM",
                })

    def _check_handler_deps(self, filepath: str, content: str) -> None:
        if filepath.endswith("requirements.txt"):
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(("boto3", "awscli", "requests")):
                    self.result.vulnerabilities.append({
                        "file": filepath,
                        "severity": "Info",
                        "description": f"Serverless dependency: {line}",
                        "type": "Dependency",
                    })

    def _check_handler_code(self, filepath: str, content: str) -> None:
        for pattern, desc, severity in SENSITIVE_HANDLER_PATTERNS:
            if re.search(pattern, content):
                self.result.vulnerabilities.append({
                    "file": filepath,
                    "severity": severity,
                    "description": f"Sensitive pattern: {desc}",
                    "type": "Handler Code",
                    "line": self._find_line(content, pattern),
                })

    def _find_line(self, content: str, pattern: str) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(pattern, line):
                return i
        return 0

    def to_findings(self, target: str = "") -> list[Finding]:
        for v in self.result.vulnerabilities:
            sev = v.get("severity", "Medium")
            cvss_map = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.5}
            cvss, vector = score_finding("ssrf")
            self.result.findings.append(
                Finding(
                    vulnerability=f"Serverless: {v['description']}",
                    severity=sev,
                    description=f"File: {v['file']} — {v['description']}",
                    target=v.get("file", target),
                    attack_type="ssrf",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation=f"Review and fix serverless configuration issue in {v.get('file', 'unknown')}.",
                )
            )
        return self.result.findings


def scan_serverless(path: str | Path) -> ServerlessScanResult:
    scanner = ServerlessScanner(path)
    return scanner.scan()
