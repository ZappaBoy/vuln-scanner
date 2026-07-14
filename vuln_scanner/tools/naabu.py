import json

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_PORTS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "22,80,443,8080,8443",
    ScanMode.PASSIVE:    "top-100",
    ScanMode.ACTIVE:     "top-1000",
    ScanMode.AGGRESSIVE: "full",
}

_RATE: dict[ScanMode, int] = {
    ScanMode.PARANOID: 100, ScanMode.PASSIVE: 500,
    ScanMode.ACTIVE: 1000,  ScanMode.AGGRESSIVE: 5000,
}


class NaabuTool(AbstractTool):
    name: str = "naabu"
    category: str = "network"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        ports = _PORTS[scan_input.mode]
        rate = scan_input.rate_limit or _RATE[scan_input.mode]
        cmd = [
            "naabu",
            "-host", host,
            "-p", ports,
            "-rate", str(rate),
            "-json",
            "-silent",
        ]
        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-nmap-cli", "nmap -sV -T3"]
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

            host = item.get("host", target)
            ip = item.get("ip", "")
            port = item.get("port", "?")
            proto = item.get("protocol", "tcp")

            findings.append(Finding(
                title=f"Open port {port}/{proto} on {host}",
                severity=Severity.INFO,
                description=f"Naabu found open port {port}/{proto} on {host}"
                            + (f" ({ip})" if ip and ip != host else ""),
                tool=self.name,
                target=host,
                raw=item,
            ))

        return findings
