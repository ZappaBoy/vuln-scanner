"""SubOver — fast, concurrent subdomain takeover scanner."""
import json
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_VULN_RE = re.compile(r"(?:Vulnerable|Takeover possible)[:\s]+(.+)", re.IGNORECASE)


class SubOverTool(AbstractTool):
    name: str = "subover"
    category: str = "takeover"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            for line in raw.splitlines():
                obj = json.loads(line)
                sub = obj.get("subdomain", "")
                service = obj.get("service", "")
                findings.append(Finding(
                    title=f"Subdomain takeover: {sub} ({service})",
                    severity=Severity.HIGH,
                    description=f"SubOver found takeover opportunity: {sub} → {service}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-350"],
                    raw=obj,
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _VULN_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"Subdomain takeover: {m.group(1).strip()[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-350"],
                        raw={"line": line},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        fd, hosts_file = tempfile.mkstemp(prefix="vs_subover_", suffix=".txt")
        start = time.monotonic()
        try:
            with os.fdopen(fd, "w") as f:
                f.write(target + "\n")
            proc = subprocess.run(
                ["subover", "-l", hosts_file, "-json"],
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
                              status=ScanStatus.FAILED, error="Binary not found: subover")
        finally:
            try:
                os.unlink(hosts_file)
            except OSError:
                pass
