"""autoSubTakeover — automated CNAME-based subdomain takeover checker."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_VULN_RE = re.compile(r"(?:Potentially vulnerable|vulnerable to takeover)[:\s]+(.+)", re.IGNORECASE)
_CNAME_RE = re.compile(r"CNAME[:\s]+(\S+)", re.IGNORECASE)


class AutoSubTakeoverTool(AbstractTool):
    name: str = "autosub-takeover"
    binary: str = "autoSubTakeover"
    category: str = "takeover"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["autoSubTakeover", "-s", target, "-o", "/dev/stdout"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                sub = m.group(1).strip()
                cname_m = _CNAME_RE.search(line)
                cname = cname_m.group(1) if cname_m else ""
                findings.append(Finding(
                    title=f"Subdomain takeover: {sub}",
                    severity=Severity.HIGH,
                    description=(
                        f"autoSubTakeover found potential takeover: {sub}"
                        + (f"\nCNAME: {cname}" if cname else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-350"],
                    raw={"subdomain": sub, "cname": cname},
                ))
        return findings
