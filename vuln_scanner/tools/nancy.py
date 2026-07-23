"""Nancy — Go dependency vulnerability scanner (Sonatype OSS Index)."""

import json
import subprocess
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


class NancyTool(AbstractTool):
    name: str = "nancy"
    binary: str = "nancy"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in data.get("vulnerable", []):
                for vuln in item.get("Vulnerabilities", []):
                    sev_str = vuln.get("CvssScore", 0)
                    sev = (
                        Severity.CRITICAL
                        if float(sev_str) >= 9
                        else Severity.HIGH
                        if float(sev_str) >= 7
                        else Severity.MEDIUM
                        if float(sev_str) >= 4
                        else Severity.LOW
                    )
                    title = vuln.get("Title", "")
                    cve_id = vuln.get("CveList", [""])[0] if vuln.get("CveList") else ""
                    pkg = item.get("Coordinates", "")
                    findings.append(
                        Finding(
                            title=f"nancy [{pkg}]: {title}",
                            severity=sev,
                            description=vuln.get("Description", title),
                            tool=self.name,
                            target=target,
                            cwe=[],
                            cve=[cve_id] if cve_id else [],
                            raw=vuln,
                        )
                    )
        except json.JSONDecodeError, ValueError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            proc_list = subprocess.run(
                ["go", "list", "-json", "-m", "all"],
                cwd=target,
                capture_output=True,
                text=True,
                timeout=60,
            )
            proc_nancy = subprocess.run(
                ["nancy", "sleuth", "--output", "json"],
                input=proc_list.stdout,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc_nancy.stdout + proc_nancy.stderr
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
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="Binary not found: nancy"
            )
