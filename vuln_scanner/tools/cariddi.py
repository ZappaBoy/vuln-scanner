import json
import subprocess
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url


class CariddiTool(AbstractTool):
    name: str = "cariddi"
    binary: str = "cariddi"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # cariddi reads URLs from stdin — target is injected via run(), not as a flag
        cmd = ["cariddi", "-s", "-json"]
        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-intensive"]
        auth = scan_input.auth
        if auth.is_configured:
            header_str = ";;".join(f"{k}: {v}" for k, v in auth.effective_headers.items())
            cmd += ["-headers", header_str]
        cmd += scan_input.extra_args
        return cmd

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=_as_url(target) + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            findings = self.parse_output(proc.stdout + proc.stderr, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=proc.stdout,
            )
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target,
                              duration=0.0, status=ScanStatus.FAILED,
                              error="Binary not found: cariddi")
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout),
                              status=ScanStatus.TIMEOUT,
                              error=f"Tool timed out after {scan_input.timeout}s")

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                if line.startswith("http"):
                    findings.append(Finding(
                        title=f"URL: {line[:100]}",
                        severity=Severity.INFO,
                        description=f"Crawled URL: {line}",
                        tool=self.name,
                        target=target,
                        raw={"url": line},
                    ))
                continue

            url = item.get("url", "")
            finding_type = item.get("type", "")
            if not url:
                continue

            sev = Severity.INFO
            if finding_type in ("secret", "credentials"):
                sev = Severity.HIGH
            elif finding_type in ("endpoint", "api"):
                sev = Severity.LOW

            findings.append(Finding(
                title=f"{finding_type or 'URL'}: {url[:100]}",
                severity=sev,
                description=f"Cariddi found: {url}" + (f" (type: {finding_type})" if finding_type else ""),
                tool=self.name,
                target=target,
                raw=item,
            ))
        return findings
