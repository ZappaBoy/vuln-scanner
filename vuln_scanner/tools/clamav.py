"""ClamAV — malware and virus scanning."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_INFECTED_RE = re.compile(r"(.+):\s+(.+?)\s+FOUND")
_SUMMARY_RE = re.compile(r"Infected files:\s+(\d+)")


class ClamAVTool(AbstractTool):
    name: str = "clamav"
    binary: str = "clamscan"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "clamscan", "--recursive", "--infected",
            "--no-summary",
            target,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _INFECTED_RE.finditer(raw):
            fname, signature = m.group(1).strip(), m.group(2).strip()
            findings.append(Finding(
                title=f"Malware detected: {signature}",
                severity=Severity.CRITICAL,
                description=f"ClamAV detected '{signature}' in file: {fname}",
                tool=self.name,
                target=target,
                cwe=["CWE-506"],
                raw={"file": fname, "signature": signature},
            ))
        return findings
