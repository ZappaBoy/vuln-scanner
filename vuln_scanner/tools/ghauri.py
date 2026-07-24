"""Ghauri — advanced cross-platform SQL injection detection tool."""

import re

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_VULN_RE = re.compile(
    r"(?:Parameter|Payload)[:\s]+([^\n]+?)(?:\s+is\s+(?:vulnerable|injectable)|$)",
    re.IGNORECASE,
)
_TECH_RE = re.compile(r"(?:back-end DBMS|technology)[:\s]+([^\n]+)", re.IGNORECASE)
_INJECTABLE_RE = re.compile(r"(\w+) (?:parameter|GET parameter) '([^']+)' is", re.IGNORECASE)


class GhauriTool(AbstractTool):
    name: str = "ghauri"
    binary: str = "ghauri"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        level = "3" if scan_input.mode == ScanMode.AGGRESSIVE else "1"
        cmd = ["ghauri", "-u", url, "--level", level, "--batch"]
        if scan_input.auth.bearer_token:
            cmd += ["--headers", f"Authorization: Bearer {scan_input.auth.bearer_token}"]
        if scan_input.auth.cookie_string:
            cmd += ["--cookie", scan_input.auth.cookie_string]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        tech = ""
        m = _TECH_RE.search(raw)
        if m:
            tech = m.group(1).strip()
        for m in _INJECTABLE_RE.finditer(raw):
            method, param = m.group(1), m.group(2)
            findings.append(
                Finding(
                    title=f"SQL Injection: {method} parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Ghauri confirmed SQL injection in {method} parameter '{param}' on {target}."
                        + (f"\nDatabase: {tech}" if tech else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-89"],
                    raw={"method": method, "parameter": param, "dbms": tech},
                )
            )
        return findings
