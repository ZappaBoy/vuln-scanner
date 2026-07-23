"""Docker Bench Security — CIS Docker benchmark."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_WARN_RE = re.compile(r"\[WARN\]\s*(.+)")
_NOTE_RE = re.compile(r"\[NOTE\]\s*(.+)")
_INFO_RE = re.compile(r"\[INFO\]\s*(.+)")


class DockerBenchTool(AbstractTool):
    name: str = "docker-bench"
    binary: str = "docker-bench-security"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["docker-bench-security", "-l", "/dev/stdout"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _WARN_RE.match(line.strip())
            if m:
                msg = m.group(1).strip()
                findings.append(
                    Finding(
                        title=f"Docker Bench [WARN]: {msg[:80]}",
                        severity=Severity.MEDIUM,
                        description=msg,
                        tool=self.name,
                        target=target,
                        cwe=["CWE-732"],
                        raw={"line": line},
                    )
                )
            n = _NOTE_RE.match(line.strip())
            if n:
                msg = n.group(1).strip()
                findings.append(
                    Finding(
                        title=f"Docker Bench [NOTE]: {msg[:80]}",
                        severity=Severity.LOW,
                        description=msg,
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"line": line},
                    )
                )
        return findings
