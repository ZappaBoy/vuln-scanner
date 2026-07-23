"""BlackWidow — Python web application scanner for OSINT and vulnerability discovery."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_VULN_RE = re.compile(r"\[VULNERABILITY\]\s*(.+)", re.IGNORECASE)
_XSS_RE = re.compile(r"\[XSS\]\s*(.+)", re.IGNORECASE)
_SQL_RE = re.compile(r"\[SQL\]\s*(.+)", re.IGNORECASE)
_URL_RE = re.compile(r"(https?://\S+)")


class BlackWidowTool(AbstractTool):
    name: str = "blackwidow"
    binary: str = "blackwidow"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        depth = "3" if scan_input.mode == ScanMode.AGGRESSIVE else "1"
        return ["blackwidow", "-u", url, "-d", depth, "-s"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if _XSS_RE.search(line):
                url_m = _URL_RE.search(line)
                findings.append(
                    Finding(
                        title=f"XSS: {(url_m.group(1) if url_m else target)[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-79"],
                        raw={"line": line},
                    )
                )
            elif _SQL_RE.search(line):
                url_m = _URL_RE.search(line)
                findings.append(
                    Finding(
                        title=f"SQLi: {(url_m.group(1) if url_m else target)[:80]}",
                        severity=Severity.CRITICAL,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-89"],
                        raw={"line": line},
                    )
                )
            elif _VULN_RE.search(line):
                findings.append(
                    Finding(
                        title=f"Vulnerability: {line[:80]}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"line": line},
                    )
                )
        return findings
