"""DevSkim — multi-language security linter (Microsoft)."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "important": Severity.HIGH,
            "moderate": Severity.MEDIUM, "low": Severity.LOW, "defense-in-depth": Severity.INFO}


class DevSkimTool(AbstractTool):
    name: str = "devskim"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["devskim", "analyze", "--source-code", target, "--output-file", "/dev/stdout",
                "--format", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for issue in (data if isinstance(data, list) else data.get("issues", [])):
                severity_str = issue.get("severity_name", "moderate").lower()
                sev = _SEV_MAP.get(severity_str, Severity.MEDIUM)
                rule_id = issue.get("rule_id", "")
                rule_name = issue.get("rule_name", "")
                fname = issue.get("file_name", "")
                line_num = issue.get("line_number", "")
                findings.append(Finding(
                    title=f"DevSkim [{rule_id}]: {rule_name}",
                    severity=sev,
                    description=f"{rule_name}\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=issue,
                ))
        except json.JSONDecodeError:
            pass
        return findings
