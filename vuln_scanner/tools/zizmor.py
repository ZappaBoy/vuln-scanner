"""zizmor — static analysis for GitHub Actions workflow files."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "information": Severity.LOW, "hint": Severity.INFO}


class ZizmorTool(AbstractTool):
    name: str = "zizmor"
    binary: str = "zizmor"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["zizmor", "--format", "json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for finding in data if isinstance(data, list) else data.get("findings", []):
                level = finding.get("determinate", {}).get("level", "warning")
                sev = _SEV_MAP.get(level, Severity.MEDIUM)
                rule = finding.get("audit", {}).get("name", "")
                msg = finding.get("message", "")
                loc = finding.get("location", {})
                fname = loc.get("file", "")
                line_num = loc.get("line", "")
                findings.append(
                    Finding(
                        title=f"zizmor [{rule}]: {msg[:80]}",
                        severity=sev,
                        description=f"{msg}\nFile: {fname}:{line_num}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-693"],
                        raw=finding,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
