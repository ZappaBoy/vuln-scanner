"""csprecon — discover new domains via Content Security Policy analysis."""
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url


class CspreconTool(AbstractTool):
    name: str = "csprecon"
    binary: str = "csprecon"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            domain = line.strip().lower()
            if domain and domain not in seen and "." in domain:
                seen.add(domain)
                findings.append(Finding(
                    title=f"CSP domain discovered: {domain}",
                    severity=Severity.INFO,
                    description=f"csprecon found domain in Content-Security-Policy header: {domain}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"domain": domain},
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["csprecon", "-u", url],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
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
                              status=ScanStatus.FAILED, error="Binary not found: csprecon")
