"""xnLinkFinder — endpoint and parameter discovery from responses and JavaScript."""

import re
import subprocess
import time

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_INTERESTING = re.compile(
    r"(?:admin|api|auth|key|token|secret|password|config|backup|\.git|\.env|internal|debug)",
    re.IGNORECASE,
)


class XnLinkFinderTool(AbstractTool):
    name: str = "xnlinkfinder"
    binary: str = "xnLinkFinder"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            endpoint = line.strip()
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            if _INTERESTING.search(endpoint):
                findings.append(
                    Finding(
                        title=f"Interesting endpoint: {endpoint[:80]}",
                        severity=Severity.LOW,
                        description=f"xnLinkFinder found endpoint: {endpoint}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-200"],
                        raw={"endpoint": endpoint},
                    )
                )
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["xnLinkFinder", "-i", url, "-sp", url, "-sf", url.split("/")[2], "-d", "2", "-o", "/dev/stdout"],
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout
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
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="xnLinkFinder not found"
            )
