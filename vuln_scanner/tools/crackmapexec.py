import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# SMB line: "SMB  192.168.1.1  445  HOSTNAME  [*] Windows 10 Build ... (name:HOSTNAME) ..."
_SMB_RE = re.compile(
    r"^SMB\s+(\S+)\s+\d+\s+(\S+)\s+\[[\+\-\*!]\]\s+(.*)"
)
_STATUS_SEV: dict[str, Severity] = {
    "+": Severity.HIGH,     # authentication success
    "-": Severity.MEDIUM,   # auth failure / negative
    "*": Severity.INFO,     # informational
    "!": Severity.MEDIUM,   # signing required / warning
}

_PROTOCOLS = {
    ScanMode.PARANOID:   "smb",
    ScanMode.PASSIVE:    "smb",
    ScanMode.ACTIVE:     "smb",
    ScanMode.AGGRESSIVE: "smb",
}


class CrackMapExecTool(AbstractTool):
    name: str = "crackmapexec"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        protocol = _PROTOCOLS.get(scan_input.mode, "smb")
        cmd = ["crackmapexec", protocol, host]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["--shares"]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--users", "--groups", "--pass-pol"]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        for line in raw.splitlines():
            # Strip ANSI escape codes
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
            m = _SMB_RE.match(clean.strip())
            if not m:
                continue

            host_addr = m.group(1)
            hostname = m.group(2)
            message = m.group(3).strip()

            # Determine status indicator from original colored line
            status_char = "*"
            indicator = re.search(r"\[(\+|\-|\*|!)\]", clean)
            if indicator:
                status_char = indicator.group(1)

            sev = _STATUS_SEV.get(status_char, Severity.INFO)

            findings.append(Finding(
                title=f"CME SMB {hostname} ({host_addr}): {message[:80]}",
                severity=sev,
                description=f"{hostname} ({host_addr}): {message}",
                tool=self.name,
                target=host_addr,
                raw={"host": host_addr, "hostname": hostname, "message": message},
            ))

        return findings
