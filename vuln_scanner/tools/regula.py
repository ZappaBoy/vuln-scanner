"""Regula — Terraform, CloudFormation IaC security scanner (OPA-based)."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class RegulaToool(AbstractTool):
    name: str = "regula"
    binary: str = "regula"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["regula", "run", "--format", "json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for result in data.get("rule_results", []):
                if result.get("rule_result") == "PASS":
                    continue
                sev_str = result.get("rule_severity", "medium").lower()
                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                rule_name = result.get("rule_name", "")
                rule_summary = result.get("rule_summary", "")
                fname = result.get("filepath", "")
                resource = result.get("resource_id", "")
                findings.append(
                    Finding(
                        title=f"Regula [{rule_name}]: {rule_summary[:80]}",
                        severity=sev,
                        description=f"{rule_summary}\nResource: {resource}\nFile: {fname}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=result,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
