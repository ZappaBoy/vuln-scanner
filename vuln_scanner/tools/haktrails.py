"""haktrails — SecurityTrails API client for subdomain and DNS history recon."""

import json

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class HaktrailsTool(AbstractTool):
    name: str = "haktrails"
    binary: str = "haktrails"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["haktrails", "subdomains", "-d", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            data = json.loads(raw)
            subdomains = data.get("subdomains", []) if isinstance(data, dict) else data
            for sub in subdomains:
                sub = str(sub).strip().lower()
                if sub and sub not in seen:
                    seen.add(sub)
                    findings.append(
                        Finding(
                            title=f"Subdomain (SecurityTrails): {sub}.{target}",
                            severity=Severity.INFO,
                            description=f"haktrails found subdomain via SecurityTrails: {sub}.{target}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"subdomain": f"{sub}.{target}"},
                        )
                    )
        except json.JSONDecodeError:
            for line in raw.splitlines():
                sub = line.strip().lower()
                if sub and sub not in seen and "." in sub:
                    seen.add(sub)
                    findings.append(
                        Finding(
                            title=f"Subdomain (SecurityTrails): {sub}",
                            severity=Severity.INFO,
                            description=f"haktrails found: {sub}",
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
