import xml.etree.ElementTree as ET

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_RATE: dict[ScanMode, int] = {
    ScanMode.PARANOID: 100,
    ScanMode.PASSIVE: 500,
    ScanMode.ACTIVE: 1000,
    ScanMode.AGGRESSIVE: 10000,
}

_PORTS: dict[ScanMode, str] = {
    ScanMode.PARANOID: "22,80,443,8080",
    ScanMode.PASSIVE: "1-1024",
    ScanMode.ACTIVE: "1-65535",
    ScanMode.AGGRESSIVE: "1-65535",
}


class MasscanTool(AbstractTool):
    name: str = "masscan"
    binary: str = "masscan"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})
    produces: frozenset[AssetType] = frozenset({AssetType.OPEN_PORT})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        rate = scan_input.rate_limit or _RATE[scan_input.mode]
        ports = _PORTS[scan_input.mode]
        cmd = [
            "masscan",
            "-p",
            ports,
            "--rate",
            str(rate),
            "--wait",
            "2",
            "-oX",
            "-",
        ]
        cmd += scan_input.extra_args
        cmd.append(target)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", target) if addr_el is not None else target

            for port_el in host.find("ports") or []:
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = port_el.get("portid", "?")
                protocol = port_el.get("protocol", "tcp")

                findings.append(
                    Finding(
                        title=f"Open port {portid}/{protocol}",
                        severity=Severity.INFO,
                        description=f"Masscan detected open port {portid}/{protocol} on {addr}.",
                        tool=self.name,
                        target=addr,
                        raw={"port": portid, "protocol": protocol},
                    )
                )

        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        assets = []
        for f in result.findings:
            port = str(f.raw.get("port", ""))
            protocol = f.raw.get("protocol", "tcp")
            service = f.raw.get("service", "unknown")
            if port:
                assets.append(Asset(
                    type=AssetType.OPEN_PORT,
                    value=f"{f.target}:{port}/{protocol}",
                    source=self.name,
                    target=result.target,
                    meta={"service": service},
                ))
        return assets
