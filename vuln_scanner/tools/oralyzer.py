"""Oralyzer — open redirect vulnerability analyzer."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_VULN_RE = re.compile(r"\[VULNERABLE\][^\n]*", re.IGNORECASE)
_REDIR_RE = re.compile(r"(?:redirect|open redirect)[^\n]*", re.IGNORECASE)
_PARAM_RE = re.compile(r"parameter[:\s]+(\S+)", re.IGNORECASE)


class OralyzerTool(AbstractTool):
    name: str = "oralyzer"
    binary: str = "oralyzer"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["oralyzer", "-s", url]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--level", "3"]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if re.search(r"VULNERABLE|open redirect found", line, re.IGNORECASE):
                param_m = _PARAM_RE.search(line)
                param = param_m.group(1) if param_m else "unknown"
                findings.append(
                    Finding(
                        title=f"Open Redirect: parameter '{param}'",
                        severity=Severity.MEDIUM,
                        description=f"Oralyzer found an open redirect vulnerability via parameter '{param}' on {target}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-601"],
                        raw={"line": line},
                    )
                )
        return findings
