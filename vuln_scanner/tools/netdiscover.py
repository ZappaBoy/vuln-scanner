import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# Netdiscover -P output line:
# " 192.168.1.1     aa:bb:cc:dd:ee:ff      1    60  Intel Corporate"
_HOST_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F:]{17})\s+"
    r"(\d+)\s+(\d+)\s+(.*?)\s*$"
)


class NetdiscoverTool(AbstractTool):
    name: str = "netdiscover"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target should be a CIDR range e.g. 192.168.1.0/24
        cmd = ["netdiscover", "-r", target, "-P", "-N"]  # -P: print-only, -N: no header

        if scan_input.mode == ScanMode.PASSIVE:
            cmd += ["-p"]   # passive mode (no ARP requests sent)

        if scan_input.rate_limit is not None:
            cmd += ["-s", str(scan_input.rate_limit)]  # sleep between each ARP request

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        for line in raw.splitlines():
            m = _HOST_RE.match(line)
            if not m:
                continue

            ip = m.group(1)
            mac = m.group(2)
            packets = m.group(3)
            vendor = m.group(5).strip()

            findings.append(Finding(
                title=f"Host discovered: {ip} ({mac})",
                severity=Severity.INFO,
                description=(
                    f"Active host {ip} with MAC {mac}"
                    + (f" ({vendor})" if vendor and vendor != "Unknown" else "")
                    + f", {packets} ARP packet(s) seen."
                ),
                tool=self.name,
                target=target,
                raw={"ip": ip, "mac": mac, "packets": packets, "vendor": vendor},
            ))

        return findings
