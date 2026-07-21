"""Retire.js — JavaScript library vulnerability detection."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW}


class RetireJSTool(AbstractTool):
    name: str = "retire-js"
    binary: str = "retire"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["retire", "--outputformat", "json", "--path", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            results = data if isinstance(data, list) else data.get("data", [])
            for file_result in results:
                fname = file_result.get("file", "")
                for result in file_result.get("results", []):
                    lib = result.get("component", "")
                    version = result.get("version", "")
                    for vuln in result.get("vulnerabilities", []):
                        severity_str = vuln.get("severity", "medium").lower()
                        sev = _SEV_MAP.get(severity_str, Severity.MEDIUM)
                        summary = vuln.get("summary", "")
                        cves = vuln.get("identifiers", {}).get("CVE", [])
                        findings.append(Finding(
                            title=f"retire.js [{lib} {version}]: {summary[:60]}",
                            severity=sev,
                            description=f"Vulnerable JS library: {lib} {version}\n{summary}\nFile: {fname}",
                            tool=self.name,
                            target=target,
                            cwe=["CWE-1035"],
                            cve=cves,
                            raw=vuln,
                        ))
        except json.JSONDecodeError:
            pass
        return findings
