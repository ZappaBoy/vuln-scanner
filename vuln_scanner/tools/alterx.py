from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class AlterxTool(AbstractTool):
    name: str = "alterx"
    binary: str = "alterx"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        cmd = ["alterx", "-d", domain, "-enrich", "-silent"]
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
                    title=f"Permutation: {subdomain}",
                    severity=Severity.INFO,
                    description=f"Subdomain permutation generated: {subdomain}",
                    tool=self.name,
                    target=target,
                    raw={"subdomain": subdomain},
                )
            )
        return findings
