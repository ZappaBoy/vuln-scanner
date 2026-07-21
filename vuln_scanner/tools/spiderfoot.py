"""SpiderFoot — automated OSINT framework (200+ modules)."""
import json
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_RISK_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
             "LOW": Severity.LOW, "INFO": Severity.INFO}


class SpiderFootTool(AbstractTool):
    name: str = "spiderfoot"
    binary: str = "sf"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.HOST, TargetType.URL, TargetType.IP,
    })

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in (data if isinstance(data, list) else []):
                risk = item.get("risk", "INFO").upper()
                sev = _RISK_MAP.get(risk, Severity.INFO)
                if sev == Severity.INFO:
                    continue
                module = item.get("module", "")
                data_str = item.get("data", "")
                findings.append(Finding(
                    title=f"SpiderFoot [{module}]: {data_str[:60]}",
                    severity=sev,
                    description=f"Module: {module}\nData: {data_str}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=item,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["sf", "-s", target, "-o", "json", "-q"],
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
                              status=ScanStatus.FAILED, error="Binary not found: sf")
