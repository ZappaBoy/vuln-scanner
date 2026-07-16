import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class GitleaksTool(AbstractTool):
    name: str = "gitleaks"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target is treated as a filesystem path or git repo path
        source = target if target.startswith("/") else "."
        cmd = [
            "gitleaks", "detect",
            "--source", source,
            "--report-format", "json",
            "--no-banner",
            "--exit-code", "0",  # don't exit 1 when leaks found
        ]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            leaks = json.loads(raw)
        except json.JSONDecodeError:
            return []

        if not isinstance(leaks, list):
            return []

        findings: list[Finding] = []
        for leak in leaks:
            rule = leak.get("RuleID", "unknown-rule")
            desc = leak.get("Description", rule)
            filepath = leak.get("File", "?")
            line = leak.get("StartLine", "?")
            findings.append(Finding(
                title=f"Secret detected: {desc} in {filepath}:{line}",
                severity=Severity.HIGH,
                description=(
                    f"Rule: {rule}\n"
                    f"File: {filepath} (line {line})\n"
                    f"Commit: {leak.get('Commit', 'N/A')}\n"
                    f"Author: {leak.get('Author', 'N/A')}"
                ),
                tool=self.name,
                target=target,
                raw=leak,
            ))
        return findings
