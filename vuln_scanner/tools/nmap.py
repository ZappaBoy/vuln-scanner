import xml.etree.ElementTree as ET

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_TIMING: dict[ScanMode, str] = {
    ScanMode.PARANOID: "-T0",
    ScanMode.PASSIVE: "-T1",
    ScanMode.ACTIVE: "-T3",
    ScanMode.AGGRESSIVE: "-T4",
}


class NmapTool(AbstractTool):
    name: str = "nmap"
    binary: str = "nmap"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})
    produces: frozenset[AssetType] = frozenset({AssetType.OPEN_PORT})
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        timing = _TIMING[scan_input.mode]
        cmd = ["nmap", timing, "-oX", "-"]

        if scan_input.mode == ScanMode.PASSIVE:
            # no TCP connect, only ping sweep + service banner
            cmd += ["-sn"]
        elif scan_input.mode == ScanMode.ACTIVE:
            cmd += ["-sV"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            # OS detection, version detection, script scanning
            cmd += ["-A"]
        # paranoid: default nmap scan, just very slow timing

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
            host_addr = addr_el.get("addr", target) if addr_el is not None else target

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = port_el.get("portid", "?")
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                service_str = service_name
                if product:
                    service_str += f" ({product} {version})".rstrip()

                findings.append(
                    Finding(
                        title=f"Open port {portid}/{protocol} — {service_str}",
                        severity=Severity.INFO,
                        description=(
                            f"Port {portid}/{protocol} is open on {host_addr}. Service detected: {service_str}."
                        ),
                        tool=self.name,
                        target=host_addr,
                        raw={"port": portid, "protocol": protocol, "service": service_name},
                    )
                )

        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        assets = []
        for f in result.findings:
            port = f.raw.get("port", "")
            protocol = f.raw.get("protocol", "tcp")
            service = f.raw.get("service", "unknown")
            if port:
                assets.append(
                    Asset(
                        type=AssetType.OPEN_PORT,
                        value=f"{f.target}:{port}/{protocol}",
                        source=self.name,
                        target=result.target,
                        meta={"service": service, "protocol": protocol},
                    )
                )
        return assets
