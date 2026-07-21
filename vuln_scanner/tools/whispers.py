"""Whispers — YAML, JSON, config file secret scanner."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW}


class WhispersTool(AbstractTool):
    name: str = "whispers"
    binary: str = "whispers"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["whispers", "--output", "json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                severity_str = obj.get("severity", "medium").lower()
                sev = _SEV_MAP.get(severity_str, Severity.MEDIUM)
                key = obj.get("key", "")
                value = obj.get("value", "***")[:20] + "..." if obj.get("value") else ""
                rule = obj.get("rule", {}).get("name", "secret")
                fname = obj.get("file", "")
                line_num = obj.get("line", "")
                findings.append(Finding(
                    title=f"Whispers [{rule}]: {key} in {fname}",
                    severity=sev,
                    description=f"Secret found: key='{key}'\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-798"],
                    raw={**obj, "value": "[REDACTED]"},
                ))
            except json.JSONDecodeError:
                continue
        return findings
