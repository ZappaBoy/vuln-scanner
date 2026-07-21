"""MVT — Mobile Verification Toolkit (forensic spyware detection)."""
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

_IOC_RE = re.compile(r"(?:indicator|ioc|compromise|detection)[:\s]+(.+)", re.IGNORECASE)


class MVTTool(AbstractTool):
    name: str = "mvt"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            detections = data.get("detections", [])
            for detection in detections:
                module = detection.get("module", "")
                indicator = detection.get("indicator", "")
                findings.append(Finding(
                    title=f"MVT IOC [{module}]: {indicator[:80]}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Mobile Verification Toolkit detected indicator of compromise:\n"
                        f"Module: {module}\nIndicator: {indicator}"
                    ),
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=detection,
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _IOC_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"MVT IOC: {m.group(1).strip()[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=[],
                        raw={"line": line},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        tmpdir = tempfile.mkdtemp(prefix="vs_mvt_")
        start = time.monotonic()
        try:
            # Detect APK vs backup
            if target.endswith(".apk"):
                cmd = ["mvt-android", "check-apks", "--apks", target, "--output", tmpdir]
            else:
                cmd = ["mvt-android", "check-backup", target, "--output", tmpdir]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=scan_input.timeout)
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            # Look for JSON results
            for fname in os.listdir(tmpdir):
                if fname.endswith(".json"):
                    try:
                        raw += open(os.path.join(tmpdir, fname)).read()
                    except OSError:
                        pass
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
                              status=ScanStatus.FAILED, error="Binary not found: mvt-android")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
