"""second-order — second-order subdomain takeover scanner (mhmdiaa/second-order)."""
import json
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_RE = re.compile(r"(?:vulnerable|takeover|dangling)[:\s]+(.+)", re.IGNORECASE)


class SecondOrderTool(AbstractTool):
    name: str = "second-order"
    category: str = "takeover"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Placeholder — run() is overridden to use a config file
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in (data if isinstance(data, list) else data.get("results", [])):
                url = item.get("url", "")
                provider = item.get("provider", "")
                findings.append(Finding(
                    title=f"Second-order takeover: {url[:80]}",
                    severity=Severity.HIGH,
                    description=f"second-order found potential second-order subdomain takeover: {url}\nProvider: {provider}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-350"],
                    raw=item,
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _VULN_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"Second-order: {m.group(1).strip()[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-350"],
                        raw={"line": line},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # second-order >= v2 dropped -base/-json flags; URL is specified via config file.
        url = _as_url(target)
        fd, cfg_path = tempfile.mkstemp(prefix="vs_second_order_", suffix=".json")
        start = time.monotonic()
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"base": url, "depth": 1}, f)
            proc = subprocess.run(
                ["second-order", "-config", cfg_path],
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
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
                              status=ScanStatus.FAILED, error="Binary not found: second-order")
        finally:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
