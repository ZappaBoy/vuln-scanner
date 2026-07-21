"""CodeQL — GitHub semantic code analysis (runs locally via CLI)."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "recommendation": Severity.LOW, "note": Severity.INFO}


class CodeQLTool(AbstractTool):
    name: str = "codeql"
    binary: str = "codeql"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                for result in obj.get("runs", [{}])[0].get("results", []):
                    rule = result.get("ruleId", "")
                    msg = result.get("message", {}).get("text", "")
                    sev_str = result.get("level", "warning")
                    sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                    locations = result.get("locations", [])
                    loc = ""
                    if locations:
                        pl = locations[0].get("physicalLocation", {})
                        af = pl.get("artifactLocation", {}).get("uri", "")
                        line_num = pl.get("region", {}).get("startLine", "")
                        loc = f"{af}:{line_num}" if line_num else af
                    findings.append(Finding(
                        title=f"CodeQL [{rule}]: {msg[:80]}",
                        severity=sev,
                        description=f"{msg}\nLocation: {loc}" if loc else msg,
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=result,
                    ))
            except (json.JSONDecodeError, IndexError):
                continue
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        db_dir = tempfile.mkdtemp(prefix="vs_codeql_db_")
        results_file = os.path.join(db_dir, "results.sarif")
        start = time.monotonic()
        try:
            # Create database
            create_cmd = [
                "codeql", "database", "create", db_dir,
                "--source-root", target,
                "--overwrite",
            ]
            subprocess.run(create_cmd, capture_output=True, text=True,
                          timeout=scan_input.timeout // 2)
            # Run analysis
            analyze_cmd = [
                "codeql", "database", "analyze", db_dir,
                "--format", "sarif-latest",
                "--output", results_file,
                "codeql/python-security-and-quality",
            ]
            proc = subprocess.run(analyze_cmd, capture_output=True, text=True,
                                 timeout=scan_input.timeout // 2)
            duration = time.monotonic() - start
            raw = ""
            if os.path.exists(results_file):
                raw = open(results_file).read()
            raw += proc.stdout + proc.stderr
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
                              status=ScanStatus.FAILED, error="Binary not found: codeql")
        finally:
            shutil.rmtree(db_dir, ignore_errors=True)
