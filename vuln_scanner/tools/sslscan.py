import xml.etree.ElementTree as ET

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_WEAK_PROTOS = {
    ("ssl", "2"): ("SSL 2.0", Severity.CRITICAL),
    ("ssl", "3"): ("SSL 3.0", Severity.HIGH),
    ("tls", "1.0"): ("TLS 1.0", Severity.MEDIUM),
    ("tls", "1.1"): ("TLS 1.1", Severity.LOW),
}

_WEAK_BITS = 128  # cipher suites below this key length are flagged


class SSLScanTool(AbstractTool):
    name: str = "sslscan"
    category: str = "ssl"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "")
        if ":" not in host:
            host = f"{host}:443"
        cmd = ["sslscan", "--xml=-", "--no-colour"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["--show-certificate", "--show-ciphers"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--show-client-cas", "--show-sigs"]

        cmd += scan_input.extra_args
        cmd.append(host)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        xml_start = raw.find("<")
        if xml_start == -1:
            return []
        try:
            root = ET.fromstring(raw[xml_start:])
        except ET.ParseError:
            return []

        findings: list[Finding] = []

        for ssltest in root.findall("ssltest"):
            host = ssltest.get("host", target)
            port = ssltest.get("port", "443")
            endpoint = f"{host}:{port}"

            # Protocol support
            for proto_el in ssltest.findall("protocol"):
                ptype = proto_el.get("type", "")
                version = proto_el.get("version", "")
                enabled = proto_el.get("enabled", "0")
                if enabled == "1":
                    key = (ptype.lower(), version)
                    if key in _WEAK_PROTOS:
                        label, sev = _WEAK_PROTOS[key]
                        findings.append(Finding(
                            title=f"Weak protocol supported: {label}",
                            severity=sev,
                            description=f"Server {endpoint} accepts {label} connections.",
                            tool=self.name,
                            target=endpoint,
                            raw={"type": ptype, "version": version},
                        ))

            # Weak ciphers
            for cipher_el in ssltest.findall("cipher"):
                status = cipher_el.get("status", "")
                if status == "rejected":
                    continue
                bits = int(cipher_el.get("bits", "256") or "256")
                cipher_name = cipher_el.get("cipher", "")
                ssl_ver = cipher_el.get("sslversion", "")

                if bits < _WEAK_BITS:
                    findings.append(Finding(
                        title=f"Weak cipher: {cipher_name} ({bits}-bit)",
                        severity=Severity.HIGH,
                        description=(
                            f"Server {endpoint} accepts weak cipher {cipher_name} "
                            f"({bits}-bit key) via {ssl_ver}."
                        ),
                        tool=self.name,
                        target=endpoint,
                        raw={"cipher": cipher_name, "bits": bits, "ssl_version": ssl_ver},
                    ))

            # Heartbleed
            for hb_el in ssltest.findall("heartbleed"):
                if hb_el.get("vulnerable", "0") == "1":
                    ssl_ver = hb_el.get("sslversion", "")
                    findings.append(Finding(
                        title=f"Heartbleed (CVE-2014-0160) on {ssl_ver}",
                        severity=Severity.CRITICAL,
                        description=f"Server {endpoint} is vulnerable to Heartbleed via {ssl_ver}.",
                        tool=self.name,
                        target=endpoint,
                        cve=["CVE-2014-0160"],
                        raw={"sslversion": ssl_ver},
                    ))

            # Certificate expiry
            cert_el = ssltest.find("certificate")
            if cert_el is not None:
                expired = cert_el.findtext("expired", "false").lower()
                self_signed = cert_el.findtext("self-signed", "false").lower()
                subject = cert_el.findtext("subject", "")

                if expired == "true":
                    findings.append(Finding(
                        title=f"Expired certificate: {subject}",
                        severity=Severity.HIGH,
                        description=f"TLS certificate on {endpoint} has expired.",
                        tool=self.name,
                        target=endpoint,
                        raw={"subject": subject, "expired": True},
                    ))
                if self_signed == "true":
                    findings.append(Finding(
                        title=f"Self-signed certificate: {subject}",
                        severity=Severity.MEDIUM,
                        description=f"TLS certificate on {endpoint} is self-signed.",
                        tool=self.name,
                        target=endpoint,
                        raw={"subject": subject, "self_signed": True},
                    ))

        return findings
