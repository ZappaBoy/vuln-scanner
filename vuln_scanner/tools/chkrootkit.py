"""chkrootkit — rootkit detection tool."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_INFECTED_RE = re.compile(r"INFECTED\s*(.+)", re.IGNORECASE)
_SUSPICIOUS_RE = re.compile(r"Suspicious files and dirs.+?found:\s*(.+)", re.IGNORECASE)
_PACKET_RE = re.compile(r"Packet sniffer files.+?found:\s*(.+)", re.IGNORECASE)


class ChkrootkitTool(AbstractTool):
    name: str = "chkrootkit"
    binary: str = "chkrootkit"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["chkrootkit", "-q"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _INFECTED_RE.search(line)
            if m:
                what = m.group(1).strip() or line.strip()
                findings.append(
                    Finding(
                        title=f"chkrootkit INFECTED: {what[:80]}",
                        severity=Severity.CRITICAL,
                        description=f"chkrootkit detected infection: {what}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-506"],
                        raw={"line": line},
                    )
                )
            elif "SUSPICIOUS" in line.upper():
                findings.append(
                    Finding(
                        title=f"chkrootkit suspicious: {line.strip()[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-506"],
                        raw={"line": line},
                    )
                )
        return findings
