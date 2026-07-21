"""findomain — fast cross-platform subdomain enumerator with certificate transparency."""
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class FindomainTool(AbstractTool):
    name: str = "findomain"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["findomain", "-t", target, "--quiet"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            sub = line.strip().lower()
            if not sub or sub in seen or " " in sub or not "." in sub:
                continue
            seen.add(sub)
            findings.append(Finding(
                title=f"Subdomain discovered: {sub}",
                severity=Severity.INFO,
                description=f"findomain found subdomain: {sub}",
                tool=self.name,
                target=target,
                cwe=[],
                raw={"subdomain": sub},
            ))
        return findings
