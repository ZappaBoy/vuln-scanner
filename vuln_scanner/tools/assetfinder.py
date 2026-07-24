"""assetfinder — find related domains and subdomains from passive sources."""

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class AssetfinderTool(AbstractTool):
    name: str = "assetfinder"
    binary: str = "assetfinder"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["assetfinder", "--subs-only", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and "." in sub:
                seen.add(sub)
                findings.append(
                    Finding(
                        title=f"Asset discovered: {sub}",
                        severity=Severity.INFO,
                        description=f"assetfinder discovered: {sub}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"subdomain": sub},
                    )
                )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["subdomain"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("subdomain")
        ]
