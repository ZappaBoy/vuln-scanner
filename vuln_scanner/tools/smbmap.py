import re
import subprocess
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

# Example smbmap line: "\tSHARENAME\tDisk\tsome comment\tREAD ONLY"
_SHARE_RE = re.compile(
    r"^\s+(\S+)\s+Disk\s*(.*?)\s+(READ ONLY|READ, WRITE|READ,WRITE|NO ACCESS|WRITE ONLY)?$",
    re.IGNORECASE,
)

_ACCESS_SEV: dict[str, Severity] = {
    "READ ONLY": Severity.MEDIUM,
    "READ, WRITE": Severity.HIGH,
    "READ,WRITE": Severity.HIGH,
    "WRITE ONLY": Severity.MEDIUM,
    "NO ACCESS": Severity.INFO,
}


class SMBMapTool(AbstractTool):
    name: str = "smbmap"
    binary: str = "smbmap"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        cmd = ["smbmap", "-H", host, "-u", "guest", "--no-pass"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-R"]  # recursive share listing

        cmd += scan_input.extra_args
        return cmd

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # smbmap exits with a non-zero code and writes to stderr when the target has no
        # SMB service or authentication fails — that is an expected (empty) result, not
        # a tool error.  Read stdout+stderr for share parsing.
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            combined = proc.stdout + proc.stderr
            findings = self.parse_output(combined, target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=combined,
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="Binary not found: smbmap"
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name,
                target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Tool timed out after {scan_input.timeout}s",
            )

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
            findings.append(
                Finding(
                    title=f"SMB share: \\\\{current_host}\\{share} [{access}]",
                    severity=sev,
                    description=(
                        f"SMB share '{share}' on {current_host}: access={access}"
                        + (f", comment={comment}" if comment else "")
                    ),
                    tool=self.name,
                    target=current_host,
                    raw={"share": share, "access": access, "comment": comment},
                )
            )

        return findings
