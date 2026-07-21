"""aemhacker — Adobe Experience Manager vulnerability scanner."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_RE = re.compile(r"(?:VULNERABLE|Found|Exposed)[:\s]+([^\n]+)", re.IGNORECASE)
_PATH_RE = re.compile(r"Path[:\s]+(\/[^\s]+)", re.IGNORECASE)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")


class AEMHackerTool(AbstractTool):
    name: str = "aemhacker"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["aemhacker", "-t", url, "--workers", "5"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                msg = m.group(1).strip()
                path_m = _PATH_RE.search(line)
                path = path_m.group(1) if path_m else ""
                cves = _CVE_RE.findall(line)
                findings.append(Finding(
                    title=f"AEM vulnerability: {msg[:80]}",
                    severity=Severity.HIGH,
                    description=f"aemhacker found: {msg}" + (f"\nPath: {path}" if path else ""),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-284"],
                    cve=cves,
                    raw={"message": msg, "path": path},
                ))
        return findings
