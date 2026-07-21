"""haktrails — SecurityTrails API client for subdomain and DNS history recon."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class HaktrailsTool(AbstractTool):
    name: str = "haktrails"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["haktrails", "subdomains", "-d", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            data = json.loads(raw)
            subdomains = data.get("subdomains", []) if isinstance(data, dict) else data
            for sub in subdomains:
                sub = str(sub).strip().lower()
                if sub and sub not in seen:
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"Subdomain (SecurityTrails): {sub}.{target}",
                        severity=Severity.INFO,
                        description=f"haktrails found subdomain via SecurityTrails: {sub}.{target}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"subdomain": f"{sub}.{target}"},
                    ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                sub = line.strip().lower()
                if sub and sub not in seen and "." in sub:
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"Subdomain (SecurityTrails): {sub}",
                        severity=Severity.INFO,
                        description=f"haktrails found: {sub}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"subdomain": sub},
                    ))
        return findings
