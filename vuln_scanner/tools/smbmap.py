import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# Example smbmap line: "\tSHARENAME\tDisk\tsome comment\tREAD ONLY"
_SHARE_RE = re.compile(
    r"^\s+(\S+)\s+Disk\s*(.*?)\s+(READ ONLY|READ, WRITE|READ,WRITE|NO ACCESS|WRITE ONLY)?$",
    re.IGNORECASE,
)

_ACCESS_SEV: dict[str, Severity] = {
    "READ ONLY":   Severity.MEDIUM,
    "READ, WRITE": Severity.HIGH,
    "READ,WRITE":  Severity.HIGH,
    "WRITE ONLY":  Severity.MEDIUM,
    "NO ACCESS":   Severity.INFO,
}


class SMBMapTool(AbstractTool):
    name: str = "smbmap"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        cmd = ["smbmap", "-H", host, "-u", "guest", "--no-pass"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-R"]   # recursive share listing

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        current_host = target

        for line in raw.splitlines():
            # Track host header lines like "[+] IP: 192.168.1.1:445   Name: host"
            host_match = re.search(r"\[\+\]\s+IP:\s+(\S+)", line)
            if host_match:
                current_host = host_match.group(1)
                continue

            match = _SHARE_RE.match(line)
            if not match:
                continue

            share = match.group(1)
            comment = (match.group(2) or "").strip()
            access = (match.group(3) or "UNKNOWN").strip().upper()

            sev = _ACCESS_SEV.get(access, Severity.INFO)
            findings.append(Finding(
                title=f"SMB share: \\\\{current_host}\\{share} [{access}]",
                severity=sev,
                description=(
                    f"SMB share '{share}' on {current_host}: access={access}"
                    + (f", comment={comment}" if comment else "")
                ),
                tool=self.name,
                target=current_host,
                raw={"share": share, "access": access, "comment": comment},
            ))

        return findings
