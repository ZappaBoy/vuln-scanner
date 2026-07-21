"""Wappalyzer CLI — technology fingerprinting from HTTP responses."""
import json
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_OUTDATED = re.compile(
    r"(?:outdated|vulnerable|eol|end-of-life|deprecated)", re.IGNORECASE,
)


class WappalyzerTool(AbstractTool):
    name: str = "wappalyzer"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Not used — run() handles the temp-file dance directly.
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # wappalyzer-next-git CLI: -i INPUT_FILE --scan-type LEVEL -oJ OUTPUT_FILE
        url = _as_url(target)
        in_fd, in_file = tempfile.mkstemp(suffix=".txt", prefix="vs_wappalyzer_in_")
        out_fd, out_file = tempfile.mkstemp(suffix=".json", prefix="vs_wappalyzer_out_")
        try:
            os.write(in_fd, (url + "\n").encode())
            os.close(in_fd)
            os.close(out_fd)
            start = time.monotonic()
            proc = subprocess.run(
                ["wappalyzer", "-i", in_file, "--scan-type", "fast", "-oJ", out_file],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            try:
                raw = open(out_file).read()
            except OSError:
                raw = proc.stdout
            return ScanResult(
                tool=self.name, target=target,
                findings=self.parse_output(raw, target),
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=(proc.stdout + proc.stderr)[:4096],
            )
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                              error=f"Tool timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED, error="Binary not found: wappalyzer")
        finally:
            for f in (in_file, out_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            technologies = data.get("technologies", data) if isinstance(data, dict) else data
            if isinstance(technologies, dict):
                technologies = list(technologies.values())
            for tech in (technologies if isinstance(technologies, list) else []):
                name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
                version = tech.get("version", "") if isinstance(tech, dict) else ""
                categories = tech.get("categories", []) if isinstance(tech, dict) else []
                cat_names = [c.get("name", "") if isinstance(c, dict) else str(c) for c in categories]
                findings.append(Finding(
                    title=f"Technology: {name}" + (f" {version}" if version else ""),
                    severity=Severity.INFO,
                    description=f"Detected: {name} {version}\nCategories: {', '.join(cat_names)}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=tech if isinstance(tech, dict) else {"name": name},
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                if line.strip() and not line.startswith("#"):
                    findings.append(Finding(
                        title=f"Technology: {line.strip()[:60]}",
                        severity=Severity.INFO,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=[],
                        raw={"line": line},
                    ))
        return findings
