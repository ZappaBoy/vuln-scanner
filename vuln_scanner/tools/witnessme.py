"""WitnessMe — web inventory tool with screenshots and default credential detection."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_DEFAULT_CRED_RE = re.compile(r"(?:default credential|default password|default login)", re.IGNORECASE)


class WitnessMeTool(AbstractTool):
    name: str = "witnessme"
    binary: str = "witnessme"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in (data if isinstance(data, list) else data.get("results", [])):
                url = item.get("url", "")
                title = item.get("title", "")
                matches = item.get("signature_matches", [])
                for match in matches:
                    sev = Severity.HIGH if _DEFAULT_CRED_RE.search(match) else Severity.MEDIUM
                    findings.append(Finding(
                        title=f"WitnessMe [{match[:40]}]: {url}",
                        severity=sev,
                        description=f"Signature match on {url}: {match}\nPage title: {title}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-521"],
                        raw=item,
                    ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        tmpdir = tempfile.mkdtemp(prefix="vs_witnessme_")
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["witnessme", "screenshot", url, "--output-dir", tmpdir],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            # Check for JSON results
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
                              status=ScanStatus.FAILED, error="Binary not found: witnessme")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
