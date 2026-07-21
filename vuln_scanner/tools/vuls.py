"""Vuls — agentless vulnerability scanner for Linux/FreeBSD (CVE-based)."""
import json
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "negligible": Severity.INFO}


class VulsTool(AbstractTool):
    name: str = "vuls"
    binary: str = "vuls"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for cve_id, cve_data in data.get("scannedCves", {}).items():
                cvss = cve_data.get("cvss3Score", {}).get("value", 0)
                sev = (Severity.CRITICAL if cvss >= 9 else Severity.HIGH if cvss >= 7
                       else Severity.MEDIUM if cvss >= 4 else Severity.LOW)
                summary = cve_data.get("cveContents", {}).get("nvd", {}).get("summary", "")
                pkgs = cve_data.get("affectedPackages", [])
                pkg_str = ", ".join(p.get("name", "") for p in pkgs)
                findings.append(Finding(
                    title=f"Vuls [{cve_id}]: {summary[:60]}",
                    severity=sev,
                    description=f"{summary}\nAffected packages: {pkg_str}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    cve=[cve_id],
                    raw=cve_data,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            # vuls scan with localhost target
            proc = subprocess.run(
                ["vuls", "scan", "-config", "/etc/vuls/config.toml"],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            # Then report as JSON
            report_proc = subprocess.run(
                ["vuls", "report", "-format-json", "-config", "/etc/vuls/config.toml"],
                capture_output=True, text=True, timeout=30,
            )
            duration = time.monotonic() - start
            raw = report_proc.stdout + report_proc.stderr
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
                              status=ScanStatus.FAILED, error="Binary not found: vuls")
