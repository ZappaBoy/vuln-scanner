"""Threagile — threat modeling as code."""

import json
import os
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_LIKELIHOOD_SEV = {
    "very-likely": Severity.CRITICAL,
    "likely": Severity.HIGH,
    "possible": Severity.MEDIUM,
    "unlikely": Severity.LOW,
    "very-unlikely": Severity.INFO,
}


class ThreagileToool(AbstractTool):
    name: str = "threagile"
    binary: str = "threagile"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for risk_id, risk in data.get("identified_risks", {}).items():
                likelihood = risk.get("exploit_likelihood", "possible").lower()
                sev = _LIKELIHOOD_SEV.get(likelihood, Severity.MEDIUM)
                title = risk.get("title", "")
                impact = risk.get("most_relevant_technical_asset", "")
                findings.append(
                    Finding(
                        title=f"Threagile [{risk_id}]: {title[:80]}",
                        severity=sev,
                        description=f"{title}\nImpact: {impact}",
                        tool=self.name,
                        target=target,
                        cwe=[risk.get("cwe", "")] if risk.get("cwe") else [],
                        raw=risk,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        tmpdir = tempfile.mkdtemp(prefix="vs_threagile_")
        start = time.monotonic()
        try:
            cmd = [
                "threagile",
                "-model",
                target,
                "-output",
                tmpdir,
                "-generate-risks-json",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
            duration = time.monotonic() - start
            risks_file = os.path.join(tmpdir, "risks.json")
            raw = proc.stdout + proc.stderr
            if os.path.exists(risks_file):
                raw += open(risks_file).read()
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
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.FAILED,
                error="Binary not found: threagile",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
