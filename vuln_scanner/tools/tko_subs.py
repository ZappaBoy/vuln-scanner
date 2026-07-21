"""tko-subs — detect and takeover subdomains with dead DNS records."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_VULN_RE = re.compile(r"\[VULNERABLE\]\s*(.+)", re.IGNORECASE)
_DEAD_RE = re.compile(r"Dead(?:DNS)?[:\s]+(.+)", re.IGNORECASE)
_SUB_RE = re.compile(r"(?:subdomain|domain)[:\s]+(\S+)", re.IGNORECASE)


class TkoSubsTool(AbstractTool):
    name: str = "tko-subs"
    category: str = "takeover"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["tko-subs", "-domains", target, "-data", "/opt/tko-subs/providers-data.csv"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line) or _DEAD_RE.search(line)
            if m:
                detail = m.group(1).strip()
                sub_m = _SUB_RE.search(line)
                sub = sub_m.group(1) if sub_m else target
                findings.append(Finding(
                    title=f"tko-subs: {detail[:80]}",
                    severity=Severity.HIGH,
                    description=f"Subdomain takeover candidate: {sub}\nDetail: {detail}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-350"],
                    raw={"subdomain": sub, "detail": detail},
                ))
        return findings
