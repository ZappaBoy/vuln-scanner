"""PMD — Java, Apex, PLSQL, XML, JS static analysis."""

import json

from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_PRIORITY_MAP = {1: Severity.HIGH, 2: Severity.HIGH, 3: Severity.MEDIUM, 4: Severity.LOW, 5: Severity.INFO}


class PMDTool(AbstractTool):
    name: str = "pmd"
    binary: str = "pmd"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "pmd",
            "check",
            "--dir",
            target,
            "--rulesets",
            "category/java/security.xml,category/java/errorprone.xml",
            "--format",
            "json",
            "--report-file",
            OUTPUT_FILE_SENTINEL,
            "--no-progress",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for file_result in data.get("files", []):
                fname = file_result.get("filename", "")
                for viol in file_result.get("violations", []):
                    priority = viol.get("priority", 3)
                    sev = _PRIORITY_MAP.get(priority, Severity.MEDIUM)
                    rule = viol.get("rule", "")
                    desc = viol.get("description", "")
                    line = viol.get("beginline", "")
                    findings.append(
                        Finding(
                            title=f"PMD [{rule}]: {desc[:60]}",
                            severity=sev,
                            description=f"{desc}\nFile: {fname}:{line}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw=viol,
                        )
                    )
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
