"""Cloudsploit — open-source cloud security scanner."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_STATUS_SEV = {"FAIL": Severity.HIGH, "WARN": Severity.MEDIUM, "PASS": Severity.INFO, "UNKNOWN": Severity.LOW}


class CloudsploitTool(AbstractTool):
    name: str = "cloudsploit"
    binary: str = "cloudsploit"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["cloudsploit", "scan", "--cloud", target.split(":")[0], "--output", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            results = data if isinstance(data, list) else data.get("results", [])
            for item in results:
                status = item.get("status", "UNKNOWN").upper()
                if status == "PASS":
                    continue
                sev = _STATUS_SEV.get(status, Severity.MEDIUM)
                plugin = item.get("plugin", "")
                category = item.get("category", "")
                message = item.get("message", "")
                findings.append(
                    Finding(
                        title=f"Cloudsploit [{category}/{plugin}]: {message[:80]}",
                        severity=sev,
                        description=f"{message}\nCategory: {category}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=item,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
