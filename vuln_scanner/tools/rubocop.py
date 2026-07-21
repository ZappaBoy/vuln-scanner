"""RuboCop — Ruby static analysis with security cops."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEVERITY_MAP = {"fatal": Severity.CRITICAL, "error": Severity.HIGH,
                 "warning": Severity.MEDIUM, "convention": Severity.LOW,
                 "refactor": Severity.INFO, "info": Severity.INFO}

_SECURITY_COPS = {"Security/", "Rails/OutputSafety", "Rails/Eval"}


class RuboCopTool(AbstractTool):
    name: str = "rubocop"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["rubocop", "--format", "json", "--only", "Security", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for file_result in data.get("files", []):
                fname = file_result.get("path", "")
                for offense in file_result.get("offenses", []):
                    cop = offense.get("cop_name", "")
                    sev_str = offense.get("severity", "warning")
                    sev = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
                    msg = offense.get("message", "")
                    loc = offense.get("location", {})
                    line_num = loc.get("start_line", "")
                    findings.append(Finding(
                        title=f"RuboCop [{cop}]: {msg[:60]}",
                        severity=sev,
                        description=f"{msg}\nFile: {fname}:{line_num}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=offense,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
