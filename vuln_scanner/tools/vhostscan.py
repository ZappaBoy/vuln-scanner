"""VHostScan — virtual host scanner with reverse lookup and wordlist support."""
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_FOUND_RE = re.compile(r"\[Found\]\s*(.+)", re.IGNORECASE)
_VHOST_RE = re.compile(r"Found virtual host:\s*(\S+)", re.IGNORECASE)


class VHostScanTool(AbstractTool):
    name: str = "vhostscan"
    binary: str = "VHostScan"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        threads = "20" if scan_input.mode == ScanMode.AGGRESSIVE else "5"
        cmd = ["VHostScan", "-t", target, "--threads", threads, "--fuzzy-logic"]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _FOUND_RE.search(line) or _VHOST_RE.search(line)
            if m:
                vhost = m.group(1).strip()
                if vhost not in seen:
                    seen.add(vhost)
                    findings.append(Finding(
                        title=f"Virtual host discovered: {vhost}",
                        severity=Severity.INFO,
                        description=f"VHostScan discovered virtual host '{vhost}' on {target}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"vhost": vhost},
                    ))
        return findings
