"""zmap — stateless large-scale internet-wide port/network scanner."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_OPEN_RE = re.compile(r"(?:open|success)[:\s]+(\S+)", re.IGNORECASE)

_DEFAULT_PORTS = {"22", "80", "443", "8080", "8443", "3306", "5432", "6379", "27017"}


class ZmapTool(AbstractTool):
    name: str = "zmap"
    binary: str = "zmap"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        rate = "100" if scan_input.mode in (ScanMode.PASSIVE, ScanMode.PARANOID) else "1000"
        cmd = ["zmap", "-p", "80", "-r", rate, "--output-filter", "success=1", target]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _IP_RE.search(line)
            if m:
                ip = m.group(1)
                if ip not in seen:
                    seen.add(ip)
                    findings.append(
                        Finding(
                            title=f"Open host: {ip}",
                            severity=Severity.INFO,
                            description=f"zmap found responsive host: {ip}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"ip": ip},
                        )
                    )
        return findings
