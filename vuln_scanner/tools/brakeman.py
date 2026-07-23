import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput

_CONFIDENCE_MAP = {"High": "high", "Medium": "medium", "Weak": "low"}


class BrakemanTool(AbstractTool):
    name: str = "brakeman"
    binary: str = "brakeman"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["brakeman", "-p", target, "-f", "json", "-q", "--no-progress"]
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
        for item in data.get("warnings", []):
            sev = _parse_severity(item.get("confidence", "medium"))
            warning_type = item.get("warning_type", "Security warning")
            message = item.get("message", "")
            filename = item.get("file", target)
            line = item.get("line", "")
            cwe = item.get("cwe", "")

            findings.append(
                Finding(
                    title=f"{warning_type}: {filename}",
                    severity=sev,
                    description=(f"{message}\nFile: {filename}" + (f"\nLine: {line}" if line else "")),
                    tool=self.name,
                    target=target,
                    cwe=([f"CWE-{cwe}"] if cwe else []),
                    references=[item.get("link", "")],
                    raw=item,
                )
            )
        return findings
