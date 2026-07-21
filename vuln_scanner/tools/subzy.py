"""Subzy — subdomain takeover scanner based on fingerprint matching."""
import json
import re
import subprocess
import tempfile
import time
import os

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus

# Plain-text fallback: "[VULNERABLE] - sub.example.com - GitHub Pages"
_VULN_RE = re.compile(
    r"\[VULNERABLE\]\s*[-–]?\s*(?P<host>\S+)\s*[-–]?\s*(?P<service>.+)",
    re.IGNORECASE,
)


class SubzyTool(AbstractTool):
    name: str = "subzy"
    binary: str = "subzy"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # built in run() — needs temp file

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Try JSON array first
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, list):
                    for entry in item:
                        if entry.get("vulnerable"):
                            host = entry.get("subdomain", target)
                            service = entry.get("service", "Unknown")
                            findings.append(self._make_finding(host, service, target, entry))
                    return findings
                if item.get("vulnerable"):
                    host = item.get("subdomain", target)
                    service = item.get("service", "Unknown")
                    findings.append(self._make_finding(host, service, target, item))
                    continue
            except json.JSONDecodeError:
                pass

            m = _VULN_RE.search(line)
            if m:
                host = m.group("host")
                service = m.group("service").strip()
                findings.append(self._make_finding(host, service, target, {"line": line}))

        return findings

    def _make_finding(self, host: str, service: str, target: str, raw: dict) -> Finding:
        return Finding(
            title=f"Subdomain takeover: {host} ({service})",
            severity=Severity.HIGH,
            description=(
                f"Subzy detected that {host} is vulnerable to takeover via {service}.\n"
                f"The CNAME or DNS record points to an unclaimed resource."
            ),
            tool=self.name,
            target=target,
            cwe=["CWE-350"],
            raw=raw,
        )

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        host = re.sub(r"^https?://", "", target).rstrip("/")
        fd, tmp = tempfile.mkstemp(prefix="vs_subzy_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(host + "\n")

            cmd = ["subzy", "run", "--targets", tmp, "--output", "json", "--hide_fails"]
            cmd += scan_input.extra_args

            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=scan_input.timeout,
                )
                duration = time.monotonic() - start
                raw = proc.stdout + proc.stderr
                return ScanResult(
                    tool=self.name, target=target, findings=self.parse_output(raw, target),
                    duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
                )
            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                    error=f"Timed out after {scan_input.timeout}s",
                )
            except FileNotFoundError:
                return ScanResult(
                    tool=self.name, target=target, duration=0.0,
                    status=ScanStatus.FAILED, error="Binary not found: subzy",
                )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
