"""waymore — extended Wayback Machine URL discovery with extended filters."""

import re

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_INTERESTING = re.compile(
    r"(?:admin|api|auth|key|token|secret|password|config|backup|\.git|\.env|\.sql|internal)",
    re.IGNORECASE,
)


class WaymoreTool(AbstractTool):
    name: str = "waymore"
    binary: str = "waymore"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})
    produces: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        return ["waymore", "-i", host, "-mode", "U", "-oU", "/dev/stdout"]

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
                        title=f"Interesting archived URL: {url[:80]}",
                        severity=Severity.LOW,
                        description=f"waymore found interesting URL from web archives: {url}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-200"],
                        raw={"url": url},
                    )
                )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.URL, value=f.raw["url"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("url", "").startswith("http")
        ]
