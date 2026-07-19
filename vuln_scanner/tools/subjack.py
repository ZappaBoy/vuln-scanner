"""Subjack — subdomain takeover detection."""
import re
import subprocess
import tempfile
import time
import os

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus

# "[Subjack] Subdomain Takeover: sub.example.com [GitHub Pages]"
# "[SubOver] Found Subdomain Takeover: sub.example.com"
_VULN_RE = re.compile(
    r"(?:Takeover|VULNERABLE|vulnerable)[:\s]+(?P<host>\S+)"
    r"(?:\s+\[(?P<service>[^\]]+)\])?",
    re.IGNORECASE,
)


class SubjackTool(AbstractTool):
    name: str = "subjack"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # built in run() — needs temp file

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if not m:
                continue
            host = m.group("host")
            service = m.group("service") or "Unknown service"
            findings.append(Finding(
                title=f"Subdomain takeover: {host} ({service})",
                severity=Severity.HIGH,
                description=(
                    f"Subdomain {host} is vulnerable to takeover via {service}.\n"
                    f"The DNS record points to a service that is not claimed."
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-350"],
                raw={"host": host, "service": service},
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        host = re.sub(r"^https?://", "", target).rstrip("/")
        fd, tmp = tempfile.mkstemp(prefix="vs_subjack_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(host + "\n")

            threads = 50 if scan_input.mode == ScanMode.AGGRESSIVE else 20
            cmd = [
                "subjack",
                "-w", tmp,
                "-t", str(threads),
                "-timeout", "30",
                "-v",
            ]
            if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
                cmd += ["-ssl"]
            cmd += scan_input.extra_args

            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=scan_input.timeout,
                )
                duration = time.monotonic() - start
                raw = proc.stdout + proc.stderr
                return ScanResult(
                    tool=self.name, target=target, findings=self.parse_output(raw, target),
                    duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
                )
            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                    error=f"Timed out after {scan_input.timeout}s",
                )
            except FileNotFoundError:
                return ScanResult(
                    tool=self.name, target=target, duration=0.0,
                    status=ScanStatus.FAILED, error="Binary not found: subjack",
                )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
