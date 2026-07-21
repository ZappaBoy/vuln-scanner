"""Psalm — PHP static analysis with security checks."""
import json
import xml.etree.ElementTree as ET

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.INFO}


class PsalmTool(AbstractTool):
    name: str = "psalm"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "psalm",
            "--output-format=json",
            "--no-progress",
            "--root", target,
            target,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            issues = data if isinstance(data, list) else data.get("issues", [])
            for issue in issues:
                issue_type = issue.get("type", "")
                sev = Severity.HIGH if "security" in issue_type.lower() else Severity.MEDIUM
                msg = issue.get("message", "")
                fname = issue.get("file_name", "")
                line_num = issue.get("line_from", "")
                if not any(k in issue_type.lower() for k in
                           ["taint", "security", "injection", "xss", "sql"]):
                    sev = Severity.LOW
                findings.append(Finding(
                    title=f"Psalm [{issue_type}]: {msg[:60]}",
                    severity=sev,
                    description=f"{msg}\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=issue,
                ))
        except json.JSONDecodeError:
            pass
        return findings
