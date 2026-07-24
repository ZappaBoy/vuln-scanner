from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class PureDNSTool(AbstractTool):
    name: str = "puredns"
    binary: str = "puredns"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Strip scheme if URL given
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        wordlist = "/usr/share/wordlists/subdomains/subdomains-top1million-5000.txt"
        cmd = [
            "puredns",
            "bruteforce",
            wordlist,
            domain,
            "--resolvers",
            "/etc/resolvers.txt",
        ]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            subdomain = line.strip()
            if not subdomain or subdomain in seen:
                continue
            seen.add(subdomain)
            findings.append(
                Finding(
                    title=f"Subdomain: {subdomain}",
                    severity=Severity.INFO,
                    description=f"Valid subdomain discovered: {subdomain}",
                    tool=self.name,
                    target=target,
                    raw={"subdomain": subdomain},
                )
            )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["subdomain"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("subdomain")
        ]
