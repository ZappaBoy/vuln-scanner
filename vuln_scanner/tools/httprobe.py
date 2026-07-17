from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class HttprobeTool(AbstractTool):
    name: str = "httprobe"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["httprobe", "-c", "20", "-prefer-https"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            findings.append(Finding(
                title=f"Live host: {url}",
                severity=Severity.INFO,
                description=f"HTTP/HTTPS service confirmed alive: {url}",
                tool=self.name,
                target=target,
                raw={"url": url},
            ))
        return findings
