"""Knockpy — subdomain enumeration using dictionary attack and DNS queries."""

import json
import re

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class KnockpyTool(AbstractTool):
    name: str = "knockpy"
    binary: str = "knockpy"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["knockpy", target, "--json", "--silent"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            for sub, info in data.items():
                if sub not in seen:
                    seen.add(sub)
                    ip = info.get("ip", [""])[0] if isinstance(info, dict) else ""
                    findings.append(
                        Finding(
                            title=f"Subdomain: {sub}",
                            severity=Severity.INFO,
                            description=f"knockpy found: {sub}" + (f" → {ip}" if ip else ""),
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"subdomain": sub, "ip": ip},
                        )
                    )
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = re.search(r"(\S+\.\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if m:
                    sub, ip = m.group(1), m.group(2)
                    if sub not in seen:
                        seen.add(sub)
                        findings.append(
                            Finding(
                                title=f"Subdomain: {sub}",
                                severity=Severity.INFO,
                                description=f"knockpy found: {sub} → {ip}",
                                tool=self.name,
                                target=target,
                                cwe=[],
                                raw={"subdomain": sub, "ip": ip},
                            )
                        )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["subdomain"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("subdomain")
        ]
