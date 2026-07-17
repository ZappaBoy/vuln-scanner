from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class WaybackURLsTool(AbstractTool):
    name: str = "waybackurls"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        cmd = ["waybackurls", domain]
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
            low = url.lower()
            sev = Severity.INFO
            if any(k in low for k in ("api", "admin", "secret", "token", "key", "pass", ".env", "backup")):
                sev = Severity.LOW
            findings.append(Finding(
                title=f"Archived URL: {url[:100]}",
                severity=sev,
                description=f"Historical URL from Wayback Machine: {url}",
                tool=self.name,
                target=target,
                raw={"url": url},
            ))
        return findings
