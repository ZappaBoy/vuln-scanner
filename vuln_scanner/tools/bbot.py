"""bbot — recursive internet scanner (subdomain, port, web, SSRF, secrets, ...)."""

import json
import re
import shutil
import subprocess
import tempfile
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_FLAG_MAP: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["passive", "safe"],
    ScanMode.PASSIVE: ["passive", "safe"],
    ScanMode.ACTIVE: ["subdomain-enum", "web-basic", "safe"],
    ScanMode.AGGRESSIVE: ["subdomain-enum", "web-thorough"],
}


class BbotTool(AbstractTool):
    name: str = "bbot"
    binary: str = "bbot"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # built in run() — needs temp output dir

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")
            data = event.get("data", {})

            if etype == "VULNERABILITY":
                if isinstance(data, dict):
                    sev_str = data.get("severity", "medium").lower()
                    desc = data.get("description", str(data))
                    host = data.get("host", target)
                    url = data.get("url", "")
                else:
                    sev_str = "medium"
                    desc = str(data)
                    host = target
                    url = ""

                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                findings.append(
                    Finding(
                        title=f"bbot: {desc[:80]}",
                        severity=sev,
                        description=f"bbot vulnerability event on {host}.\n{desc}" + (f"\nURL: {url}" if url else ""),
                        tool=self.name,
                        target=target,
                        raw=event,
                    )
                )

            elif etype == "FINDING":
                if isinstance(data, dict):
                    desc = data.get("description", str(data))
                    host = data.get("host", target)
                else:
                    desc = str(data)
                    host = target
                findings.append(
                    Finding(
                        title=f"bbot finding: {desc[:80]}",
                        severity=Severity.INFO,
                        description=f"bbot finding on {host}.\n{desc}",
                        tool=self.name,
                        target=target,
                        raw=event,
                    )
                )

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        host = re.sub(r"^https?://", "", target).rstrip("/")
        tmpdir = tempfile.mkdtemp(prefix="vs_bbot_")
        start = time.monotonic()

        flags = _FLAG_MAP.get(scan_input.mode, _FLAG_MAP[ScanMode.PASSIVE])
        cmd = [
            "bbot",
            "-t",
            host,
            "-f",
            *flags,
            "--output-modules",
            "json",
            "-o",
            tmpdir,
            "--force",
            "--silent",
        ]
        cmd += list(scan_input.extra_args)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start

            # bbot writes output.ndjson under tmpdir/<scan_name>/json/
            raw_out = ""
            import glob
            import os

            for ndjson in glob.glob(os.path.join(tmpdir, "**", "*.ndjson"), recursive=True):
                try:
                    raw_out += open(ndjson).read() + "\n"
                except OSError:
                    pass
            if not raw_out:
                raw_out = proc.stdout + proc.stderr

            return ScanResult(
                tool=self.name,
                target=target,
                findings=self.parse_output(raw_out, target),
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc.stdout + proc.stderr,
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
                error="Binary not found: bbot",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
