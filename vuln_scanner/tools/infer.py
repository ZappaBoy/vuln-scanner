"""Infer — Facebook static analyser for Java, C, C++, Objective-C."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_BUG_TYPE_SEV = {
    "NULL_DEREFERENCE": Severity.HIGH,
    "RESOURCE_LEAK": Severity.MEDIUM,
    "MEMORY_LEAK": Severity.HIGH,
    "USE_AFTER_FREE": Severity.CRITICAL,
    "BUFFER_OVERRUN": Severity.HIGH,
    "INFERBO": Severity.MEDIUM,
    "TAINT": Severity.HIGH,
}


class InferTool(AbstractTool):
    name: str = "infer"
    binary: str = "infer"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["infer", "run", "--keep-going", "--", "make", "-C", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        import os
        report_path = os.path.join("infer-out", "report.json")
        if not os.path.exists(report_path):
            report_path = os.path.join(target, "infer-out", "report.json")
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                for bug in data:
                    bug_type = bug.get("bug_type", "")
                    sev = _BUG_TYPE_SEV.get(bug_type, Severity.MEDIUM)
                    msg = bug.get("qualifier", "")
                    fname = bug.get("file", "")
                    line_num = bug.get("line", "")
                    findings.append(Finding(
                        title=f"Infer [{bug_type}]: {msg[:80]}",
                        severity=sev,
                        description=f"{msg}\nFile: {fname}:{line_num}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=bug,
                    ))
            except (json.JSONDecodeError, OSError):
                pass
        return findings
