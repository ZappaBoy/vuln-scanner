import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class NoseyParkerTool(AbstractTool):
    name: str = "noseyparker"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "noseyparker", "scan",
            "--datastore", "/tmp/vs_noseyparker_ds",
            target,
        ]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for match in data.get("matches", data if isinstance(data, list) else []):
            rule_name = match.get("rule_name", "Secret")
            snippet = match.get("snippet", {})
            loc = match.get("location", {})
            filepath = loc.get("path", target)
            line = loc.get("start_line", "")
            matching_input = snippet.get("matching", "")

            findings.append(Finding(
                title=f"Secret: {rule_name} in {filepath}",
                severity=Severity.CRITICAL,
                description=(
                    f"Potential secret found: {rule_name}\n"
                    f"File: {filepath}" + (f"\nLine: {line}" if line else "")
                    + (f"\nSnippet: {matching_input[:100]}" if matching_input else "")
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-798"],
                raw=match,
            ))
        return findings
