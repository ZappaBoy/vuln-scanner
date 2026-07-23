"""ProgPilot — PHP SAST tool for detecting security vulnerabilities."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_VULN_SEV = {
    "sql_injection": Severity.CRITICAL,
    "xss": Severity.HIGH,
    "code_injection": Severity.CRITICAL,
    "file_include": Severity.HIGH,
    "path_traversal": Severity.HIGH,
    "command_injection": Severity.CRITICAL,
    "ssrf": Severity.HIGH,
    "xml_injection": Severity.MEDIUM,
    "ldap_injection": Severity.HIGH,
    "header_injection": Severity.MEDIUM,
}


class ProgPilotTool(AbstractTool):
    name: str = "progpilot"
    binary: str = "progpilot"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["progpilot", "--path", target, "--format", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for vuln in vulns:
                vuln_type = vuln.get("type", "").lower().replace(" ", "_")
                sev = _VULN_SEV.get(vuln_type, Severity.MEDIUM)
                name = vuln.get("vuln_name", vuln_type)
                source = vuln.get("source_name", "")
                fname = vuln.get("source_file", "")
                line_num = vuln.get("source_line", "")
                findings.append(
                    Finding(
                        title=f"ProgPilot [{name}] via {source}",
                        severity=sev,
                        description=f"Vulnerability: {name}\nSource: {source}\nFile: {fname}:{line_num}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=vuln,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
