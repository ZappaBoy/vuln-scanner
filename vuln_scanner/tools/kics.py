"""KICS — Checkmarx open-source IaC security scanner."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}


class KICSTool(AbstractTool):
    name: str = "kics"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "kics", "scan",
            "--path", target,
            "--output-path", "/dev/stdout",
            "--report-formats", "json",
            "--no-progress",
            "--silent",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for query in data.get("queries", []):
                sev_str = query.get("severity", "medium").lower()
                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                query_name = query.get("query_name", "")
                for file_result in query.get("files", []):
                    fname = file_result.get("file_name", "")
                    line_num = file_result.get("line", "")
                    issue_type = file_result.get("issue_type", "")
                    findings.append(Finding(
                        title=f"KICS [{query_name}]: {issue_type or fname}",
                        severity=sev,
                        description=f"Query: {query_name}\nFile: {fname}:{line_num}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=file_result,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
