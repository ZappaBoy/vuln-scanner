"""CMSmap — open-source multi-CMS security scanner (WordPress, Joomla, Drupal)."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_CRIT_RE = re.compile(r"\[C\]\s*(.+)", re.IGNORECASE)
_HIGH_RE = re.compile(r"\[H\]\s*(.+)", re.IGNORECASE)
_MED_RE = re.compile(r"\[M\]\s*(.+)", re.IGNORECASE)
_LOW_RE = re.compile(r"\[L\]\s*(.+)", re.IGNORECASE)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")

_SEVERITY_MAP = [
    (_CRIT_RE, Severity.CRITICAL),
    (_HIGH_RE, Severity.HIGH),
    (_MED_RE, Severity.MEDIUM),
    (_LOW_RE, Severity.LOW),
]


class CMSmapTool(AbstractTool):
    name: str = "cmsmap"
    binary: str = "cmsmap"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["cmsmap", url, "--noedb", "-q"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            for pattern, sev in _SEVERITY_MAP:
                m = pattern.match(line.strip())
                if m:
                    msg = m.group(1).strip()
                    cves = _CVE_RE.findall(msg)
                    findings.append(
                        Finding(
                            title=f"CMSmap: {msg[:80]}",
                            severity=sev,
                            description=msg,
                            tool=self.name,
                            target=target,
                            cwe=["CWE-693"],
                            cve=cves,
                            raw={"line": line},
                        )
                    )
                    break
        return findings
