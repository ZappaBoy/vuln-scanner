"""hakip2host — resolve IP ranges to associated domain names via reverse DNS."""

import re
import subprocess
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_RESULT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(.+)")


class HakIp2HostTool(AbstractTool):
    name: str = "hakip2host"
    binary: str = "hakip2host"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _RESULT_RE.match(line.strip())
            if m:
                ip, hostname = m.group(1), m.group(2).strip()
                key = f"{ip}:{hostname}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            title=f"IP to hostname: {ip} → {hostname}",
                            severity=Severity.INFO,
                            description=f"Reverse DNS: {ip} → {hostname}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"ip": ip, "hostname": hostname},
                        )
                    )
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["hakip2host"],
                input=target + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            return ScanResult(
                tool=self.name,
                target=target,
                findings=self.parse_output(raw, target),
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name,
                target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.FAILED,
                error="Binary not found: hakip2host",
            )
