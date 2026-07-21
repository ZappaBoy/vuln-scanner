"""Joern — code property graph for multi-language semantic vulnerability analysis."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_VULN_RE = re.compile(r"(?:vulnerability|issue|finding)[:\s]+([^\n]+)", re.IGNORECASE)


class JoernTool(AbstractTool):
    name: str = "joern"
    binary: str = "joern"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                msg = m.group(1).strip()
                findings.append(Finding(
                    title=f"Joern: {msg[:80]}",
                    severity=Severity.MEDIUM,
                    description=msg,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"line": line},
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        tmpdir = tempfile.mkdtemp(prefix="vs_joern_")
        results_file = os.path.join(tmpdir, "results.json")
        start = time.monotonic()
        try:
            script = (
                f'importCode(inputPath="{target}", projectName="scan"); '
                f'println(cpg.finding.toJsonPretty); exit;'
            )
            proc = subprocess.run(
                ["joern", "--script", "/dev/stdin"],
                input=script,
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
                              status=ScanStatus.FAILED, error="Binary not found: joern")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
