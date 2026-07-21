import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class SubfinderTool(AbstractTool):
    name: str = "subfinder"
    binary: str = "subfinder"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target should be a domain (e.g. example.com)
        cmd = ["subfinder", "-d", target, "-json", "-silent"]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            cmd += ["-sources", "passive"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-all"]

        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = item.get("host", "")
            if not host:
                continue

            ip = item.get("ip", "")
            source = item.get("source", "")
            findings.append(Finding(
                title=f"Subdomain: {host}",
                severity=Severity.INFO,
                description=(
                    f"Discovered subdomain: {host}"
                    + (f" ({ip})" if ip else "")
                    + (f" via {source}" if source else "")
                ),
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings
