"""QARK — Android static analysis tool."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP = {
    5: Severity.CRITICAL,
    4: Severity.HIGH,
    3: Severity.MEDIUM,
    2: Severity.LOW,
    1: Severity.INFO,
    0: Severity.INFO,
}


class QARKTool(AbstractTool):
    name: str = "qark"
    binary: str = "qark"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["qark", "--apk", target, "--report-type", "json", "--output", "/dev/stdout"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for issue in data.get("issues", []):
                severity_num = int(issue.get("severity", 2))
                sev = _SEV_MAP.get(severity_num, Severity.MEDIUM)
                name = issue.get("name", "")
                desc = issue.get("description", "")
                findings.append(
                    Finding(
                        title=f"QARK [{name}]: {desc[:80]}",
                        severity=sev,
                        description=desc,
                        tool=self.name,
                        target=target,
                        cwe=[issue.get("cwe", "")] if issue.get("cwe") else [],
                        raw=issue,
                    )
                )
        except json.JSONDecodeError, ValueError:
            pass
        return findings
