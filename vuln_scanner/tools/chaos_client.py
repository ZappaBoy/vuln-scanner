"""chaos-client — Go client for ProjectDiscovery Chaos DNS API (passive subdomain recon)."""
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class ChaosClientTool(AbstractTool):
    name: str = "chaos-client"
    binary: str = "chaos"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["chaos", "-d", target, "-silent"]
        if scan_input.auth.bearer_token:
            cmd += ["-key", scan_input.auth.bearer_token]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and "." in sub:
                seen.add(sub)
                findings.append(Finding(
                    title=f"Subdomain (Chaos): {sub}",
                    severity=Severity.INFO,
                    description=f"chaos-client found subdomain via Chaos API: {sub}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"subdomain": sub},
                ))
        return findings
