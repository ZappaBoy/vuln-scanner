"""Jaeles — Swiss Army knife for automated web application testing (rule-based)."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class JaelesTool(AbstractTool):
    name: str = "jaeles"
    binary: str = "jaeles"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                sev = _SEV_MAP.get(obj.get("severity", "").lower(), Severity.INFO)
                findings.append(
                    Finding(
                        title=obj.get("title", "Jaeles finding"),
                        severity=sev,
                        description=obj.get("desc", ""),
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=obj,
                    )
                )
            except json.JSONDecodeError:
                if re.search(r"\[V\]|\[VULN\]", line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            title=f"Jaeles finding: {line[:80]}",
                            severity=Severity.MEDIUM,
                            description=line.strip(),
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"line": line},
                        )
                    )
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        tmpdir = tempfile.mkdtemp(prefix="vs_jaeles_")
        start = time.monotonic()
        try:
            cmd = [
                "jaeles",
                "scan",
                "-u",
                url,
                "--output",
                tmpdir,
                "--json",
            ]
            if scan_input.mode in (ScanMode.PASSIVE, ScanMode.PARANOID):
                cmd += ["-s", "sensitive"]
            if scan_input.proxy:
                cmd += ["--proxy", scan_input.proxy]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            # Merge all JSON files in output dir
            for root, _, files in os.walk(tmpdir):
                for fname in files:
                    if fname.endswith(".json"):
                        try:
                            raw += open(os.path.join(root, fname)).read()
                        except OSError:
                            pass
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
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="Binary not found: jaeles"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
