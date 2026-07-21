"""ReconFTW — automated full-scope reconnaissance framework."""
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_VULN_RE = re.compile(r"(?:VULN|VULNERABILITY|CRITICAL|HIGH)[:\s]+(.+)", re.IGNORECASE)
_SUB_RE = re.compile(r"(?:Subdomain|Found)[:\s]+(\S+\.\S+)", re.IGNORECASE)
_TAKEOVER_RE = re.compile(r"(?:takeover|VULNERABLE)[:\s]+(.+)", re.IGNORECASE)


class ReconFTWTool(AbstractTool):
    name: str = "reconftw"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                findings.append(Finding(
                    title=f"ReconFTW finding: {m.group(1).strip()[:80]}",
                    severity=Severity.HIGH,
                    description=line.strip(),
                    tool=self.name, target=target, cwe=[],
                    raw={"line": line},
                ))
            elif _TAKEOVER_RE.search(line):
                findings.append(Finding(
                    title=f"ReconFTW takeover: {line.strip()[:80]}",
                    severity=Severity.HIGH,
                    description=line.strip(),
                    tool=self.name, target=target, cwe=["CWE-350"],
                    raw={"line": line},
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        tmpdir = tempfile.mkdtemp(prefix="vs_reconftw_")
        start = time.monotonic()
        try:
            mode_flag = "-a" if scan_input.mode == ScanMode.AGGRESSIVE else "-s"
            proc = subprocess.run(
                ["reconftw.sh", "-d", target, mode_flag, "--output", tmpdir],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            # Read summary if available
            summary = os.path.join(tmpdir, "reconftw_main.txt")
            if os.path.exists(summary):
                raw += open(summary).read()
            return ScanResult(
                tool=self.name, target=target,
                findings=self.parse_output(raw, target),
                duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED, error="Binary not found: reconftw.sh")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
