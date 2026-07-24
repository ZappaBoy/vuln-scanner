"""Photon — fast OSINT web crawler (extracts URLs, emails, keys, files)."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_INTERESTING = re.compile(
    r"(?:api|key|secret|token|password|admin|internal|config|backup|\.git|\.env)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class PhotonTool(AbstractTool):
    name: str = "photon"
    binary: str = "photon"
    category: str = "osint"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for url in data.get("urls", []):
                if _INTERESTING.search(url):
                    findings.append(
                        Finding(
                            title=f"Interesting URL: {url[:80]}",
                            severity=Severity.LOW,
                            description=f"Photon found interesting URL: {url}",
                            tool=self.name,
                            target=target,
                            cwe=["CWE-200"],
                            raw={"url": url},
                        )
                    )
            for email in data.get("emails", []):
                findings.append(
                    Finding(
                        title=f"Email discovered: {email}",
                        severity=Severity.INFO,
                        description=f"Photon found email address: {email}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"email": email},
                    )
                )
            for key in data.get("keys", []):
                findings.append(
                    Finding(
                        title=f"Credential/key exposed: {key[:60]}",
                        severity=Severity.HIGH,
                        description=f"Photon found potential credential: {key}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-798"],
                        raw={"key": "[REDACTED]"},
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.URL, value=f.raw["url"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("url", "").startswith("http")
        ]

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        tmpdir = tempfile.mkdtemp(prefix="vs_photon_")
        start = time.monotonic()
        try:
            depth = "3" if scan_input.mode == ScanMode.AGGRESSIVE else "1"
            proc = subprocess.run(
                ["python3", "/opt/photon/photon.py", "-u", url, "-l", depth, "-o", tmpdir, "--only-urls", "--json"],
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            # Merge JSON output files
            for fname in os.listdir(tmpdir):
                if fname.endswith(".json"):
                    try:
                        raw += open(os.path.join(tmpdir, fname)).read()
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
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.FAILED,
                error="Photon not found at /opt/photon",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
