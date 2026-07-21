"""AST-based code analysis for AI-generated application vulnerabilities."""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)


AI_GENERATED_PATTERNS = [
    (r"def\s+\w+\(.*\):\s*\n\s+return\s+\w+\.\w+\(.*\)", "Thin wrapper pattern", "Low"),
    (r"for\s+\w+\s+in\s+range\(\d+\):\s*\n\s+print\(", "Generic loop with print", "Info"),
    (r"try:\s*\n\s+.*\n(?:except\s+Exception\s*as\s+\w+:\s*\n\s+pass\s*\n?){1,}", "Bare except: pass", "Medium"),
    (r"except\s*:\s*\n\s+pass", "Bare except clause", "Medium"),
    (r"eval\(.*input\(|exec\(.*input\(|compile\(.*input\(", "Dynamic code from input", "Critical"),
]

SECURITY_SINK_PATTERNS: list[dict] = [
    {"pattern": r"\.execute\(.*\+", "name": "String concatenation in SQL query", "severity": "Critical", "attack_type": "sqli"},
    {"pattern": r"\.query\(.*f[\"']", "name": "F-string in SQL query", "severity": "Critical", "attack_type": "sqli"},
    {"pattern": r"\.format\(.*[\"'].*SELECT", "name": "format() in SQL query", "severity": "High", "attack_type": "sqli"},
    {"pattern": r"innerHTML\s*=.*\+", "name": "String concat in innerHTML", "severity": "High", "attack_type": "xss"},
    {"pattern": r"document\.write\(.*\+", "name": "String concat in document.write", "severity": "High", "attack_type": "xss"},
    {"pattern": r"dangerouslySetInnerHTML", "name": "dangerouslySetInnerHTML in React", "severity": "High", "attack_type": "xss"},
    {"pattern": r"v-html\s*=", "name": "v-html binding in Vue", "severity": "Medium", "attack_type": "xss"},
    {"pattern": r"eval\(|exec\(|execScript\(", "name": "Dynamic code execution", "severity": "Critical", "attack_type": "cmdi"},
    {"pattern": r"subprocess\.(call|Popen|run).*shell=True", "name": "Shell=True in subprocess", "severity": "Critical", "attack_type": "cmdi"},
    {"pattern": r"os\.system\(|os\.popen\(", "name": "OS command execution", "severity": "Critical", "attack_type": "cmdi"},
    {"pattern": r"pickle\.loads\(|yaml\.load\([^S]", "name": "Unsafe deserialization", "severity": "Critical", "attack_type": "zero_day"},
    {"pattern": r"__import__\(|importlib\.import_module\(.*input", "name": "Dynamic import from input", "severity": "High", "attack_type": "zero_day"},
    {"pattern": r"render_template_string\(|Template\(.*input", "name": "SSTI via template string", "severity": "Critical", "attack_type": "ssti"},
    {"pattern": r"requests\.get\(.*input|requests\.post\(.*input", "name": "SSRF via user input", "severity": "High", "attack_type": "ssrf"},
    {"pattern": r"redirect\(.*input|redirect\(.*request", "name": "Open redirect from input", "severity": "Medium", "attack_type": "open_redirect"},
    {"pattern": r"assert\s+.*True|assert\s+.*False", "name": "Assert used for validation", "severity": "Low", "attack_type": "business_logic"},
]


@dataclass
class ASTIssue:
    line: int
    column: int
    name: str
    severity: str
    attack_type: str
    snippet: str


@dataclass
class ASTAnalysisResult:
    file_path: str = ""
    issues: list[ASTIssue] = field(default_factory=list)
    total_lines: int = 0
    findings: list[Finding] = field(default_factory=list)


class ASTAnalyzer:
    """Analyze source code AST for security vulnerabilities."""

    def analyze_file(self, filepath: str | Path) -> ASTAnalysisResult:
        path = Path(filepath)
        result = ASTAnalysisResult(file_path=str(path))

        if not path.exists() or path.suffix not in (".py", ".js", ".ts", ".tsx", ".jsx"):
            return result

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result.total_lines = len(content.splitlines())
        except Exception as e:
            logger.debug("Cannot read %s: %s", path, e)
            return result

        if path.suffix == ".py":
            self._analyze_python(content, result)
        else:
            self._analyze_js_ts(content, result)

        return result

    def _analyze_python(self, content: str, result: ASTAnalysisResult) -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call_safety(node, content, result)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                self._check_string_concat(node, content, result)

        for issue in AST_ISSUES:
            result.issues.append(issue)

        for pattern, name, severity in AI_GENERATED_PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE):
                result.issues.append(ASTIssue(
                    line=content[:match.start()].count("\n") + 1,
                    column=match.start() % 80,
                    name=name,
                    severity=severity,
                    attack_type="business_logic",
                    snippet=match.group()[:80],
                ))

    def _check_call_safety(self, node: ast.Call, content: str, result: ASTAnalysisResult) -> None:
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        unsafe_calls = {"eval": "Critical", "exec": "Critical", "compile": "High"}
        if func_name in unsafe_calls:
            result.issues.append(ASTIssue(
                line=node.lineno,
                column=node.col_offset,
                name=f"Unsafe call: {func_name}()",
                severity=unsafe_calls[func_name],
                attack_type="zero_day",
                snippet=content.splitlines()[node.lineno - 1].strip()[:80] if node.lineno <= len(content.splitlines()) else func_name,
            ))

    def _check_string_concat(self, node: ast.BinOp, content: str, result: ASTAnalysisResult) -> None:
        left = isinstance(node.left, ast.Str)
        right = isinstance(node.right, ast.Str)
        if not (left or right):
            result.issues.append(ASTIssue(
                line=node.lineno,
                column=node.col_offset,
                name="String concatenation with non-literals",
                severity="Low",
                attack_type="business_logic",
                snippet=content.splitlines()[node.lineno - 1].strip()[:80] if node.lineno <= len(content.splitlines()) else "",
            ))

    def _analyze_js_ts(self, content: str, result: ASTAnalysisResult) -> None:
        for entry in SECURITY_SINK_PATTERNS:
            for match in re.finditer(entry["pattern"], content):
                line_num = content[:match.start()].count("\n") + 1
                result.issues.append(ASTIssue(
                    line=line_num,
                    column=match.start() % 80,
                    name=entry["name"],
                    severity=entry["severity"],
                    attack_type=entry["attack_type"],
                    snippet=match.group()[:80],
                ))

    def to_findings(self, result: ASTAnalysisResult) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for issue in result.issues:
            key = f"{issue.line}:{issue.name}"
            if key in seen:
                continue
            seen.add(key)

            cvss, vector = score_finding(issue.attack_type)
            findings.append(
                Finding(
                    vulnerability=f"AST Analysis: {issue.name}",
                    severity=issue.severity,
                    description=f"File: {result.file_path}:{issue.line} | {issue.name}. Snippet: {issue.snippet[:60]}",
                    target=result.file_path,
                    attack_type=issue.attack_type,
                    payload=issue.snippet[:100],
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation=f"Fix '{issue.name}' at line {issue.line}. Refer to OWASP guidelines for secure coding.",
                )
            )

        return findings


AST_ISSUES: list[ASTIssue] = []


def analyze_source(path: str | Path) -> list[Finding]:
    p = Path(path)
    analyzer = ASTAnalyzer()
    all_findings: list[Finding] = []

    if p.is_file():
        result = analyzer.analyze_file(p)
        all_findings.extend(analyzer.to_findings(result))
    elif p.is_dir():
        for ext in ("**/*.py", "**/*.js", "**/*.ts", "**/*.tsx", "**/*.jsx"):
            for f in sorted(p.glob(ext)):
                if any(ignored in str(f) for ignored in ("node_modules", ".git", "venv", "__pycache__")):
                    continue
                result = analyzer.analyze_file(f)
                all_findings.extend(analyzer.to_findings(result))

    return all_findings
