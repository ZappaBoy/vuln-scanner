"""rkhunter — rootkit, backdoor, and local exploit detection."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_WARNING_RE = re.compile(r"Warning:\s+(.+)", re.IGNORECASE)
_FOUND_RE = re.compile(r"Found\s+(.+)", re.IGNORECASE)
_ROOTKIT_RE = re.compile(r"(?:Rootkit|backdoor|trojan)[:\s]+(.+)", re.IGNORECASE)


class RkhunterTool(AbstractTool):
    name: str = "rkhunter"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["rkhunter", "--check", "--skip-keypress", "--nocolors"]
        if target and target != "localhost":
            cmd += ["--rwo"]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            warn_m = _WARNING_RE.search(line)
            rootkit_m = _ROOTKIT_RE.search(line)
            if rootkit_m:
                msg = rootkit_m.group(1).strip()
                findings.append(Finding(
                    title=f"Rootkit/backdoor: {msg[:80]}",
                    severity=Severity.CRITICAL,
                    description=f"rkhunter detected: {msg}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-506"],
                    raw={"line": line},
                ))
            elif warn_m:
                msg = warn_m.group(1).strip()
                findings.append(Finding(
                    title=f"rkhunter warning: {msg[:80]}",
                    severity=Severity.HIGH,
                    description=msg,
                    tool=self.name,
                    target=target,
                    cwe=["CWE-506"],
                    raw={"line": line},
                ))
        return findings
