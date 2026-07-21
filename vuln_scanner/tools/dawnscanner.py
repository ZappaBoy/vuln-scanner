"""DawnScanner — Ruby security scanner."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
_VULN_RE = re.compile(r"\[CVE-\d{4}-\d+\]|\[OWASP[^\]]+\]", re.IGNORECASE)


class DawnScannerTool(AbstractTool):
    name: str = "dawnscanner"
    binary: str = "dawn"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["dawn", "--json", "--quiet", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for issue in data.get("vulnerabilities", []):
                name = issue.get("name", "")
                sev_str = issue.get("severity", "medium").lower()
                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                desc = issue.get("description", "")
                fname = issue.get("filename", "")
                line_num = issue.get("line", "")
                cves = [c for c in issue.get("cve", "").split(",") if c.strip()]
                findings.append(Finding(
                    title=f"DawnScanner: {name}",
                    severity=sev,
                    description=f"{desc}\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    cve=cves,
                    raw=issue,
                ))
        except json.JSONDecodeError:
            pass
        return findings
