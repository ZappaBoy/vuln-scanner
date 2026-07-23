import json
import subprocess
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class HorusecTool(AbstractTool):
    name: str = "horusec"
    binary: str = "horusec"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "horusec",
            "start",
            "-p",
            target,
            "-o",
            "json",
            "--disable-docker",
            "true",
        ]
        cmd += scan_input.extra_args
        return cmd

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # horusec is installed via yay with `|| true` — skip gracefully if absent.
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
            duration = time.monotonic() - start
            findings = self.parse_output(proc.stdout + proc.stderr, target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc.stdout,
            )
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target, duration=0.0, status=ScanStatus.SKIPPED)
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name,
                target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Tool timed out after {scan_input.timeout}s",
            )

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        analysis = data.get("analysisVulnerabilities", [])
        for item in analysis:
            vuln = item.get("vulnerabilities", item)
            sev = _parse_severity(vuln.get("severity", "medium"))
            title = vuln.get("details", vuln.get("vulnHash", "Horusec finding"))[:80]
            filename = vuln.get("file", target)
            line = vuln.get("line", "")
            code = vuln.get("code", "")
            security_tool = vuln.get("securityTool", "")

            findings.append(
                Finding(
                    title=title,
                    severity=sev,
                    description=(
                        f"{title}\n"
                        f"File: {filename}"
                        + (f"\nLine: {line}" if line else "")
                        + (f"\nCode: {code[:200]}" if code else "")
                        + (f"\nDetected by: {security_tool}" if security_tool else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=([f"CWE-{vuln['cwe']}"] if vuln.get("cwe") else []),
                    raw=vuln,
                )
            )
        return findings
