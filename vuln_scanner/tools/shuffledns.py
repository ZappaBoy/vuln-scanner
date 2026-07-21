"""shuffledns — massdns wrapper with active bruteforce and wildcard filtering."""
import os

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
_RESOLVERS = "/usr/share/massdns/resolvers.txt"


class ShuffleDNSTool(AbstractTool):
    name: str = "shuffledns"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        wordlist = _WORDLIST if os.path.exists(_WORDLIST) else ""
        resolvers = _RESOLVERS if os.path.exists(_RESOLVERS) else ""
        cmd = ["shuffledns", "-d", target, "-silent"]
        if wordlist:
            cmd += ["-w", wordlist]
        if resolvers:
            cmd += ["-r", resolvers]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and "." in sub:
                seen.add(sub)
                findings.append(Finding(
                    title=f"Subdomain resolved: {sub}",
                    severity=Severity.INFO,
                    description=f"shuffledns resolved subdomain: {sub}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"subdomain": sub},
                ))
        return findings
