import json

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    Severity,
)


class SSLyzeTool(AbstractTool):
    name: str = "sslyze"
    category: str = "ssl"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "")
        if ":" not in host:
            host = f"{host}:443"
        cmd = ["sslyze", "--json_out=-"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["--heartbleed", "--robot", "--compression", "--reneg"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--early_data", "--openssl_ccs", "--fallback"]

        cmd += scan_input.extra_args
        cmd.append(host)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for result in data.get("server_scan_results", []):
            scan = result.get("scan_result") or {}
            host = result.get("server_location", {}).get("hostname", target)

            # Deprecated/weak protocols
            for proto, label in [
                ("ssl_2_0_cipher_suites", "SSL 2.0"),
                ("ssl_3_0_cipher_suites", "SSL 3.0"),
                ("tls_1_0_cipher_suites", "TLS 1.0"),
                ("tls_1_1_cipher_suites", "TLS 1.1"),
            ]:
                block = scan.get(proto, {})
                accepted = (block.get("result") or {}).get("accepted_cipher_suites", [])
                if accepted:
                    sev = Severity.HIGH if "ssl" in proto else Severity.MEDIUM
                    findings.append(Finding(
                        title=f"Weak protocol supported: {label}",
                        severity=sev,
                        description=f"Server accepts {label} connections ({len(accepted)} cipher suite(s)).",
                        tool=self.name,
                        target=host,
                        raw={"protocol": proto, "accepted": len(accepted)},
                    ))

            # Heartbleed
            hb = (scan.get("heartbleed") or {}).get("result") or {}
            if hb.get("is_vulnerable_to_heartbleed"):
                findings.append(Finding(
                    title="Heartbleed (CVE-2014-0160)",
                    severity=Severity.CRITICAL,
                    description="Server is vulnerable to the Heartbleed OpenSSL bug.",
                    tool=self.name,
                    target=host,
                    cve=["CVE-2014-0160"],
                ))

            # ROBOT
            robot = (scan.get("robot") or {}).get("result") or {}
            if "NOT_VULNERABLE" not in str(robot.get("robot_result", "NOT_VULNERABLE")):
                findings.append(Finding(
                    title="ROBOT Attack",
                    severity=Severity.HIGH,
                    description="Server may be vulnerable to the ROBOT (Return Of Bleichenbacher's Oracle Threat) attack.",
                    tool=self.name,
                    target=host,
                    cve=["CVE-2017-13099"],
                ))

            # Compression (CRIME)
            comp = (scan.get("tls_compression") or {}).get("result") or {}
            if comp.get("supports_compression"):
                findings.append(Finding(
                    title="TLS Compression enabled (CRIME)",
                    severity=Severity.MEDIUM,
                    description="Server supports TLS compression, making it potentially vulnerable to the CRIME attack.",
                    tool=self.name,
                    target=host,
                    cve=["CVE-2012-4929"],
                ))

        return findings
