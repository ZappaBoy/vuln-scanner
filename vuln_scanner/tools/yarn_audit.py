"""Yarn audit — Node.js dependency vulnerability scanner."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}


class YarnAuditTool(AbstractTool):
    name: str = "yarn-audit"
    binary: str = "yarn"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["yarn", "--cwd", target, "audit", "--json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "auditAdvisory":
                    advisory = obj.get("data", {}).get("advisory", {})
                    sev_str = advisory.get("severity", "medium").lower()
                    sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                    title = advisory.get("title", "")
                    module = advisory.get("module_name", "")
                    cves = advisory.get("cves", [])
                    desc = advisory.get("overview", "")
                    findings.append(Finding(
                        title=f"yarn audit [{module}]: {title}",
                        severity=sev,
                        description=desc,
                        tool=self.name,
                        target=target,
                        cwe=[advisory.get("cwe", "")] if advisory.get("cwe") else [],
                        cve=cves,
                        raw=advisory,
                    ))
            except json.JSONDecodeError:
                continue
        return findings
