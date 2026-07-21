"""SSRFmap — automatic SSRF fuzzer and exploitation tool."""
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_RE = re.compile(r"\[\+\]\s*(SSRF[^\n]+)", re.IGNORECASE)


class SSRFmapTool(AbstractTool):
    name: str = "ssrfmap"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # uses custom run() due to request file requirement

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _VULN_RE.finditer(raw):
            findings.append(Finding(
                title=f"SSRF vulnerability: {m.group(1).strip()}",
                severity=Severity.HIGH,
                description=f"SSRFmap detected: {m.group(1).strip()}",
                tool=self.name,
                target=target,
                cwe=["CWE-918"],
                raw={"match": m.group(1)},
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        fd, req_file = tempfile.mkstemp(prefix="vs_ssrfmap_", suffix=".txt")
        start = time.monotonic()
        try:
            with os.fdopen(fd, "w") as f:
                f.write(f"GET / HTTP/1.1\nHost: {target}\nURL: {url}\n")
            cmd = [
                "python3", "/opt/SSRFmap/ssrfmap.py",
                "-r", req_file,
                "--level", "2" if scan_input.mode == ScanMode.AGGRESSIVE else "1",
            ]
            if scan_input.proxy:
                cmd += ["--proxy", scan_input.proxy]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
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
                              status=ScanStatus.FAILED, error="SSRFmap not found at /opt/SSRFmap")
        finally:
            try:
                os.unlink(req_file)
            except OSError:
                pass
