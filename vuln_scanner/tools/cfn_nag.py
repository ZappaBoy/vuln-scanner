"""cfn-nag — AWS CloudFormation security linting."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class CfnNagTool(AbstractTool):
    name: str = "cfn-nag"
    binary: str = "cfn_nag_scan"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["cfn_nag_scan", "--input-path", target, "--output-format", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for file_result in (data if isinstance(data, list) else [data]):
                fname = file_result.get("filename", "")
                for violation in file_result.get("file_results", {}).get("violations", []):
                    vtype = violation.get("type", "WARN")
                    sev = Severity.HIGH if vtype == "FAIL" else Severity.MEDIUM
                    rule_id = violation.get("id", "")
                    msg = violation.get("message", "")
                    resources = violation.get("logical_resource_ids", [])
                    findings.append(Finding(
                        title=f"cfn-nag [{rule_id}]: {msg[:80]}",
                        severity=sev,
                        description=f"{msg}\nResources: {', '.join(resources)}\nFile: {fname}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=violation,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
