import json

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class AmassTool(AbstractTool):
    name: str = "amass"
    binary: str = "amass"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target should be a domain name (e.g. example.com)
        cmd = ["amass", "enum", "-d", target, "-json", OUTPUT_FILE_SENTINEL]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            cmd += ["-passive"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-brute", "-w", "/usr/share/amass/wordlists/subdomains-top1mil-5000.txt"]

        if scan_input.rate_limit is not None:
            # amass uses queries per minute
            cmd += ["-max-dns-queries", str(scan_input.rate_limit * 60)]

        cmd += ["-timeout", str(max(1, scan_input.timeout // 60))]  # amass uses minutes
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            name = item.get("name", "")
            addresses = item.get("addresses", [])
            ips = [a.get("ip", "") for a in addresses if a.get("ip")]
            source = item.get("source", item.get("tag", ""))

            findings.append(
                Finding(
                    title=f"Subdomain: {name}",
                    severity=Severity.INFO,
                    description=(f"Discovered subdomain: {name}\nIPs: {', '.join(ips) or 'N/A'}\nSource: {source}"),
                    tool=self.name,
                    target=target,
                    raw=item,
                )
            )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        assets = []
        for f in result.findings:
            name = f.raw.get("name", "")
            if name:
                assets.append(Asset(type=AssetType.SUBDOMAIN, value=name, source=self.name, target=result.target))
        return assets

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
