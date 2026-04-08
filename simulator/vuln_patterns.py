"""
Vulnerability scanner using regex + AST patterns.

Detects:
  - SQLi            : f-string / % / .format() interpolation in SQL queries
  - missing_auth    : route handlers without @require_auth decorator
  - ssrf            : urllib / requests calls with unsanitized user-supplied URLs
  - rce             : subprocess(shell=True) or eval() on user input
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class VulnMatch:
    vuln_type: str
    file: str
    line: int
    description: str
    severity: str = "high"


class VulnScanner:

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, filename: str, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        findings.extend(self._check_sqli(filename, source))
        findings.extend(self._check_ssrf(filename, source))
        findings.extend(self._check_rce(filename, source))
        findings.extend(self._check_missing_auth_ast(filename, source))
        return findings

    def scan_codebase(self, files: dict[str, str]) -> List[VulnMatch]:
        all_findings: List[VulnMatch] = []
        for fname, src in files.items():
            if fname.endswith(".py") and src.strip():
                all_findings.extend(self.scan_file(fname, src))
        return all_findings

    # ------------------------------------------------------------------
    # SQLi – regex on source lines
    # ------------------------------------------------------------------

    _SQL_KEYWORDS = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b",
        re.IGNORECASE,
    )
    _INTERPOLATION = re.compile(
        r'(f["\'].*?["\']|%\s*\w|\.(format|replace)\s*\()',
        re.DOTALL,
    )

    def _check_sqli(self, filename: str, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            if self._SQL_KEYWORDS.search(line) and self._INTERPOLATION.search(line):
                findings.append(VulnMatch(
                    vuln_type="sqli",
                    file=filename,
                    line=lineno,
                    description=(
                        "Possible SQL injection: user-controlled data interpolated "
                        "directly into SQL query string"
                    ),
                    severity="critical",
                ))
        return findings

    # ------------------------------------------------------------------
    # SSRF – urllib/requests call with variable URL
    # ------------------------------------------------------------------

    _SSRF_RE = re.compile(
        r"\b(urllib\.request\.urlopen|requests\.(get|post|put|delete|head|request))\s*\(",
    )

    def _check_ssrf(self, filename: str, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            if self._SSRF_RE.search(line):
                # Only flag if argument looks like a variable (not a literal)
                if not re.search(r'["\']https?://', line):
                    findings.append(VulnMatch(
                        vuln_type="ssrf",
                        file=filename,
                        line=lineno,
                        description=(
                            "Potential SSRF: HTTP call with unsanitized URL "
                            "that may reach internal services"
                        ),
                        severity="high",
                    ))
        return findings

    # ------------------------------------------------------------------
    # RCE – subprocess(shell=True) or eval()
    # ------------------------------------------------------------------

    _RCE_PATTERNS = [
        (re.compile(r"subprocess\.(run|Popen|call|check_output).*shell\s*=\s*True"), "command injection via shell=True"),
        (re.compile(r"\beval\s*\("),                                                  "eval() of potentially untrusted input"),
        (re.compile(r"\bexec\s*\("),                                                  "exec() of potentially untrusted input"),
        (re.compile(r"os\.(system|popen)\s*\("),                                      "os.system/popen with potential user input"),
    ]

    def _check_rce(self, filename: str, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            for pattern, desc in self._RCE_PATTERNS:
                if pattern.search(line):
                    findings.append(VulnMatch(
                        vuln_type="rce",
                        file=filename,
                        line=lineno,
                        description=f"Remote code execution risk: {desc}",
                        severity="critical",
                    ))
        return findings

    # ------------------------------------------------------------------
    # Missing auth – AST: route handler without @require_auth
    # ------------------------------------------------------------------

    def _check_missing_auth_ast(self, filename: str, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            has_route = False
            has_auth = False
            for decorator in node.decorator_list:
                dec_str = ast.unparse(decorator)
                if ".route(" in dec_str:
                    has_route = True
                if "require_auth" in dec_str or "login_required" in dec_str:
                    has_auth = True
            if has_route and not has_auth:
                findings.append(VulnMatch(
                    vuln_type="missing_auth",
                    file=filename,
                    line=node.lineno,
                    description=(
                        f"Route handler '{node.name}' has no authentication decorator; "
                        "endpoint is publicly accessible"
                    ),
                    severity="high",
                ))
        return findings
