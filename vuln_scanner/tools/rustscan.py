import xml.etree.ElementTree as ET

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_ULIMIT: dict[ScanMode, int] = {
    ScanMode.PARANOID: 500,
    ScanMode.PASSIVE: 1000,
    ScanMode.ACTIVE: 5000,
    ScanMode.AGGRESSIVE: 10000,
}

_PORTS: dict[ScanMode, str | None] = {
    ScanMode.PARANOID: "22,80,443,8080",
    ScanMode.PASSIVE: None,  # rustscan default (~top 1000)
    ScanMode.ACTIVE: None,  # full range via --range flag
    ScanMode.AGGRESSIVE: None,
}

_RANGE: dict[ScanMode, str | None] = {
    ScanMode.PARANOID: None,
    ScanMode.PASSIVE: "1-1024",
    ScanMode.ACTIVE: "1-65535",
    ScanMode.AGGRESSIVE: "1-65535",
}

_NMAP_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: [],
    ScanMode.PASSIVE: ["-sV"],
    ScanMode.ACTIVE: ["-sV"],
    ScanMode.AGGRESSIVE: ["-A"],
}


class RustScanTool(AbstractTool):
    name: str = "rustscan"
    binary: str = "rustscan"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        ulimit = _ULIMIT[scan_input.mode]
        nmap_flags = _NMAP_FLAGS[scan_input.mode] + ["-oX", "-"]
        cmd = ["rustscan", "-a", target, "--ulimit", str(ulimit)]
        ports = _PORTS[scan_input.mode]
        if ports is not None:
            cmd += ["-p", ports]
        port_range = _RANGE[scan_input.mode]
        if port_range is not None:
            cmd += ["--range", port_range]
        cmd += ["--"] + nmap_flags
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        # RustScan passes output to nmap; nmap writes XML to stdout
        xml_start = raw.find("<?xml")
        if xml_start == -1:
            xml_start = raw.find("<nmaprun")
        if xml_start == -1:
            return []

        raw_xml = raw[xml_start:]
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", target) if addr_el is not None else target

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
                service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                label = service
                if product:
                    label += f" ({product} {version})".rstrip()

                findings.append(
                    Finding(
                        title=f"Open port {portid}/{protocol} — {label}",
                        severity=Severity.INFO,
                        description=f"Port {portid}/{protocol} is open on {addr}. Service: {label}.",
                        tool=self.name,
                        target=addr,
                        raw={"port": portid, "protocol": protocol, "service": service},
                    )
                )

        return findings
