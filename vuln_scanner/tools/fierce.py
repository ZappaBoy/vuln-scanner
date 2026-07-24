import re

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SUBDOMAIN_RE = re.compile(r"Found:\s+(\S+)\s+(?:==>|->)?\s*(\d{1,3}(?:\.\d{1,3}){3})?")
_ZONE_RE = re.compile(r"zone transfer", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"wildcard", re.IGNORECASE)


class FierceTool(AbstractTool):
    name: str = "fierce"
    binary: str = "fierce"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = ["fierce", "--domain", domain]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--subdomains", "/usr/share/wordlists/fierce/hosts.txt"]
        elif scan_input.mode == ScanMode.ACTIVE:
            cmd += ["--subdomains", "/usr/share/fierce/hosts.txt"]

        if scan_input.rate_limit is not None:
            cmd += ["--delay", str(max(0, 1 // scan_input.rate_limit))]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # Zone transfer success
            if _ZONE_RE.search(line) and "success" in line.lower():
                findings.append(
                    Finding(
                        title="DNS zone transfer succeeded",
                        severity=Severity.CRITICAL,
                        description=f"DNS zone transfer was successful for {target}: {line}",
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line},
                    )
                )
                continue

            # Wildcard DNS
            if _WILDCARD_RE.search(line):
                findings.append(
                    Finding(
                        title="Wildcard DNS detected",
                        severity=Severity.LOW,
                        description=f"Wildcard DNS record detected for {target}: {line}",
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line},
                    )
                )
                continue

            # Subdomain → IP
            m = _SUBDOMAIN_RE.search(line)
            if m:
                subdomain = m.group(1)
                ip = m.group(2) or ""
                key = subdomain
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        title=f"Subdomain: {subdomain}" + (f" ({ip})" if ip else ""),
                        severity=Severity.INFO,
                        description=f"Discovered subdomain: {subdomain}" + (f" → {ip}" if ip else ""),
                        tool=self.name,
                        target=target,
                        raw={"subdomain": subdomain, "ip": ip},
                    )
                )

        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["subdomain"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("subdomain")
        ]
