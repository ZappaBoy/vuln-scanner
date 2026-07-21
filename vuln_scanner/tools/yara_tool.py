"""YARA — malware pattern matching rules engine."""
import os
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_MATCH_RE = re.compile(r"(\S+)\s+(\S+)")
_RULE_DIRS = [
    "/usr/share/yara/rules",
    "/opt/yara-rules",
    "/etc/yara",
]


class YARATool(AbstractTool):
    name: str = "yara"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _MATCH_RE.match(line.strip())
            if m:
                rule, fpath = m.group(1), m.group(2)
                key = f"{rule}:{fpath}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"YARA rule match: {rule}",
                        severity=Severity.HIGH,
                        description=f"YARA rule '{rule}' matched in: {fpath}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-506"],
                        raw={"rule": rule, "file": fpath},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # Find rules directory
        rules_dir = next((d for d in _RULE_DIRS if os.path.isdir(d)), None)
        if not rules_dir:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED, error="No YARA rules directory found")
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["yara", "-r", os.path.join(rules_dir, "*.yar"), target],
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
                              status=ScanStatus.FAILED, error="Binary not found: yara")
