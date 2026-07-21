import csv
import io

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


def _level_to_severity(level: str) -> Severity:
    try:
        lvl = int(level)
    except ValueError:
        return Severity.INFO
    if lvl >= 4:
        return Severity.HIGH
    if lvl == 3:
        return Severity.MEDIUM
    if lvl == 2:
        return Severity.LOW
    return Severity.INFO


class FlawfinderTool(AbstractTool):
    name: str = "flawfinder"
    binary: str = "flawfinder"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["flawfinder", "--csv", "--quiet", target]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            filename = row.get("File", target)
            line = row.get("Line", "")
            level = row.get("Level", "0")
            category = row.get("Category", "")
            name = row.get("Name", "")
            warning = row.get("Warning", "")
            context = row.get("Context", "")
            sev = _level_to_severity(level)

            findings.append(Finding(
                title=f"{name}: {filename}",
                severity=sev,
                description=(
                    f"{warning}\n"
                    f"File: {filename}" + (f"\nLine: {line}" if line else "")
                    + (f"\nContext: {context[:200]}" if context else "")
                    + (f"\nCategory: {category}" if category else "")
                ),
                tool=self.name,
                target=target,
                raw=dict(row),
            ))
        return findings
