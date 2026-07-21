import json
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_DETAIL: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "NORMAL",
    ScanMode.PASSIVE:    "NORMAL",
    ScanMode.ACTIVE:     "DETAILED",
    ScanMode.AGGRESSIVE: "ALL",
}

_VULN_SEV: dict[str, tuple[Severity, list[str]]] = {
    "Heartbleed":     (Severity.CRITICAL, ["CVE-2014-0160"]),
    "POODLE":         (Severity.HIGH,     ["CVE-2014-3566"]),
    "BEAST":          (Severity.MEDIUM,   ["CVE-2011-3389"]),
    "CRIME":          (Severity.MEDIUM,   ["CVE-2012-4929"]),
    "BREACH":         (Severity.MEDIUM,   ["CVE-2013-3587"]),
    "FREAK":          (Severity.HIGH,     ["CVE-2015-0204"]),
    "LOGJAM":         (Severity.MEDIUM,   ["CVE-2015-4000"]),
    "DROWN":          (Severity.HIGH,     ["CVE-2016-0800"]),
    "ROBOT":          (Severity.HIGH,     ["CVE-2017-13099"]),
    "RACCOON":        (Severity.MEDIUM,   ["CVE-2020-1968"]),
    "Lucky13":        (Severity.MEDIUM,   ["CVE-2013-0169"]),
    "SweetBEAST":     (Severity.MEDIUM,   []),
    "PaddingOracle":  (Severity.HIGH,     []),
    "EarlyFinished":  (Severity.MEDIUM,   []),
    "InvalidCurve":   (Severity.HIGH,     []),
    "CertificateIssue": (Severity.HIGH,   []),
}


class TLSAttackerTool(AbstractTool):
    name: str = "tls-attacker"
    binary: str = "TLS-Scanner"
    category: str = "ssl"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "")
        if ":" not in host:
            host = f"{host}:443"
        detail = _DETAIL.get(scan_input.mode, "NORMAL")
        cmd = [
            "TLS-Scanner",
            "-connect", host,
            "-reportFormat", "JSON",
            "-reportDetail", detail,
            "-report", OUTPUT_FILE_SENTINEL,
        ]

        if scan_input.mode == ScanMode.PARANOID:
            cmd += ["-parallelProbes", "1"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-parallelProbes", "4"]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        host = data.get("host", target)

        # Protocol support
        versions = data.get("versions") or data.get("supportedVersions") or []
        for v in versions:
            vname = v if isinstance(v, str) else v.get("version", "")
            if vname.upper() in ("SSL2", "SSL3", "TLS10", "TLS11", "SSLV2", "SSLV3"):
                sev_map = {
                    "SSL2": Severity.CRITICAL, "SSLV2": Severity.CRITICAL,
                    "SSL3": Severity.HIGH,     "SSLV3": Severity.HIGH,
                    "TLS10": Severity.MEDIUM,
                    "TLS11": Severity.LOW,
                }
                sev = sev_map.get(vname.upper(), Severity.MEDIUM)
                findings.append(Finding(
                    title=f"Weak protocol supported: {vname}",
                    severity=sev,
                    description=f"Server {host} supports deprecated protocol {vname}.",
                    tool=self.name,
                    target=host,
                    raw={"version": vname},
                ))

        # Vulnerabilities
        vulns = data.get("vulnerabilities") or {}
        if isinstance(vulns, dict):
            items = vulns.items()
        elif isinstance(vulns, list):
            items = ((v.get("name", "?"), v) for v in vulns)
        else:
            items = []

        for vuln_name, vuln_info in items:
            # Normalise: could be a bool True, or dict with "vulnerable" key
            if isinstance(vuln_info, bool):
                vulnerable = vuln_info
                detail_str = ""
            elif isinstance(vuln_info, dict):
                vulnerable = vuln_info.get("vulnerable", False)
                detail_str = vuln_info.get("description", "")
            else:
                continue

            if not vulnerable:
                continue

            sev, cves = _VULN_SEV.get(vuln_name, (Severity.MEDIUM, []))
            findings.append(Finding(
                title=f"TLS vulnerability: {vuln_name}",
                severity=sev,
                description=(
                    f"Server {host} is vulnerable to {vuln_name}."
                    + (f" {detail_str}" if detail_str else "")
                ),
                tool=self.name,
                target=host,
                cve=cves,
                raw={"vulnerability": vuln_name},
            ))

        # Weak ciphers
        weak_ciphers = data.get("weakCiphers") or data.get("supported_ciphersuites") or []
        for cipher in weak_ciphers:
            name = cipher if isinstance(cipher, str) else cipher.get("name", str(cipher))
            if re.search(r"(NULL|EXPORT|RC4|DES|MD5|anon)", name, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Weak/null cipher: {name}",
                    severity=Severity.HIGH,
                    description=f"Server {host} supports insecure cipher suite: {name}.",
                    tool=self.name,
                    target=host,
                    raw={"cipher": name},
                ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
