"""kxss — finds reflected XSS parameters in HTTP responses."""
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_FOUND_RE = re.compile(r"(https?://\S+)")


class KxssTool(AbstractTool):
    name: str = "kxss"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # piped command handled in run()

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _FOUND_RE.search(line)
            if m and m.group(1) not in seen:
                url = m.group(1)
                seen.add(url)
                findings.append(Finding(
                    title=f"Reflected XSS parameter: {url}",
                    severity=Severity.HIGH,
                    description=f"kxss detected a potentially reflected XSS parameter in: {url}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-79"],
                    raw={"url": url},
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["kxss"],
                input=url + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
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
                              status=ScanStatus.FAILED, error="Binary not found: kxss")
