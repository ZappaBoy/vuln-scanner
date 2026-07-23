"""ScoutSuite — multi-cloud audit (AWS, Azure, GCP, Alibaba)."""

import json
import os
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_LEVEL_MAP = {"danger": Severity.HIGH, "warning": Severity.MEDIUM, "good": Severity.INFO, "neutral": Severity.INFO}


class ScoutSuiteTool(AbstractTool):
    name: str = "scoutsuite"
    binary: str = "scout"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for service, service_data in data.get("services", {}).items():
                for finding_id, finding_data in service_data.get("findings", {}).items():
                    level = finding_data.get("level", "neutral")
                    if level in ("good", "neutral"):
                        continue
                    sev = _LEVEL_MAP.get(level, Severity.MEDIUM)
                    description = finding_data.get("description", "")
                    items_count = finding_data.get("items_count", 0)
                    findings.append(
                        Finding(
                            title=f"ScoutSuite [{service}]: {description[:80]}",
                            severity=sev,
                            description=f"{description}\nAffected items: {items_count}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw={"service": service, "id": finding_id, "level": level},
                        )
                    )
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        tmpdir = tempfile.mkdtemp(prefix="vs_scoutsuite_")
        start = time.monotonic()
        try:
            # Infer cloud provider from target string
            provider = "aws"
            if "azure" in target.lower():
                provider = "azure"
            elif "gcp" in target.lower() or "google" in target.lower():
                provider = "gcp"
            cmd = [
                "scout",
                provider,
                "--report-dir",
                tmpdir,
                "--no-browser",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
            duration = time.monotonic() - start
            # Look for results JSON
            raw = proc.stdout + proc.stderr
            for fname in os.listdir(tmpdir):
                if fname.endswith(".json"):
                    try:
                        raw += open(os.path.join(tmpdir, fname)).read()
                        break
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
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="Binary not found: scout"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
