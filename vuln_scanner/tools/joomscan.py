"""joomscan — OWASP Joomla vulnerability scanner."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_RE = re.compile(r"\[!\]\s*(.+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"Joomla\s+([\d.]+)", re.IGNORECASE)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
_COMPONENT_RE = re.compile(r"Component[:\s]+([^\n]+)", re.IGNORECASE)


class JoomscanTool(AbstractTool):
    name: str = "joomscan"
    binary: str = "joomscan"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["joomscan", "-u", url, "--enumerate-components"]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.match(line.strip())
            if not m:
                continue
            msg = m.group(1).strip()
            cves = _CVE_RE.findall(line)
            sev = Severity.HIGH if cves else Severity.MEDIUM
            findings.append(Finding(
                title=f"Joomla issue: {msg[:80]}",
                severity=sev,
                description=msg,
                tool=self.name,
                target=target,
                cwe=["CWE-693"],
                cve=cves,
                raw={"line": line},
            ))
        return findings
