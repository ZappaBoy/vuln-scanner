import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_EXPIRED_SEV   = Severity.HIGH
_SELF_SIGN_SEV = Severity.MEDIUM
_WEAK_PROTO    = {"ssl2.0", "ssl3.0", "tls1.0", "tls1.1"}


class TlsxTool(AbstractTool):
    name: str = "tlsx"
    binary: str = "tlsx"
    category: str = "ssl"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "")
        if ":" not in host:
            host = f"{host}:443"
        cmd = ["tlsx", "-host", host, "-json", "-silent", "-san", "-cn", "-so"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-tls-version", "-cipher", "-hash", "md5,sha1,sha256"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-expired", "-self-signed", "-mismatched"]

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
            tls_version = item.get("tls_version", item.get("version", ""))
            subject = item.get("subject_cn", item.get("subject", ""))
            cipher = item.get("cipher", "")
            expired = item.get("expired", False)
            self_signed = item.get("self_signed", False)
            mismatched = item.get("mismatched", False)

            # Informational: TLS version + cert
            findings.append(Finding(
                title=f"TLS: {host} — {tls_version}" + (f" ({subject})" if subject else ""),
                severity=Severity.INFO,
                description=(
                    f"TLS connection to {host}: version={tls_version}, subject={subject}"
                    + (f", cipher={cipher}" if cipher else "")
                ),
                tool=self.name,
                target=host,
                raw=item,
            ))

            # Weak protocol
            if tls_version.lower().replace(" ", "").replace("v", "") in _WEAK_PROTO:
                findings.append(Finding(
                    title=f"Weak TLS protocol: {tls_version}",
                    severity=Severity.MEDIUM if "tls1" in tls_version.lower() else Severity.HIGH,
                    description=f"Host {host} uses deprecated protocol {tls_version}.",
                    tool=self.name,
                    target=host,
                    raw={"tls_version": tls_version},
                ))

            if expired:
                findings.append(Finding(
                    title=f"Expired certificate on {host}",
                    severity=_EXPIRED_SEV,
                    description=f"TLS certificate on {host} has expired.",
                    tool=self.name,
                    target=host,
                    raw={"expired": True, "subject": subject},
                ))

            if self_signed:
                findings.append(Finding(
                    title=f"Self-signed certificate on {host}",
                    severity=_SELF_SIGN_SEV,
                    description=f"TLS certificate on {host} is self-signed.",
                    tool=self.name,
                    target=host,
                    raw={"self_signed": True, "subject": subject},
                ))

            if mismatched:
                findings.append(Finding(
                    title=f"Certificate hostname mismatch on {host}",
                    severity=Severity.HIGH,
                    description=f"Certificate subject '{subject}' does not match host '{host}'.",
                    tool=self.name,
                    target=host,
                    raw={"mismatched": True, "subject": subject},
                ))

        return findings
