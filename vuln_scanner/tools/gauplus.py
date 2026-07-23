"""gauplus — extended URL gathering from Wayback Machine, CommonCrawl, OTX."""

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_INTERESTING = __import__("re").compile(
    r"(?:admin|api|auth|config|backup|\.git|\.env|secret|key|token|password|debug|upload|internal)",
    __import__("re").IGNORECASE,
)


class GauplusTool(AbstractTool):
    name: str = "gauplus"
    binary: str = "gauplus"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = ["gauplus", host]
        if scan_input.proxy:
            cmd += ["-p", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            if _INTERESTING.search(url):
                findings.append(
                    Finding(
                        title=f"Interesting URL from archives: {url[:80]}",
                        severity=Severity.LOW,
                        description=f"gauplus found interesting archived URL: {url}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-200"],
                        raw={"url": url},
                    )
                )
        return findings
