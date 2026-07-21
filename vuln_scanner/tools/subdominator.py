"""subdominator — fast subdomain enumeration aggregating 50+ passive sources."""
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class SubdominatorTool(AbstractTool):
    name: str = "subdominator"
    binary: str = "subdominator"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["subdominator", "-d", target, "-silent"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and "." in sub:
                seen.add(sub)
                findings.append(Finding(
                    title=f"Subdomain: {sub}",
                    severity=Severity.INFO,
                    description=f"subdominator found: {sub}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"subdomain": sub},
                ))
        return findings
