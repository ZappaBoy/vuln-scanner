import subprocess
import time

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class HttprobeTool(AbstractTool):
    name: str = "httprobe"
    binary: str = "httprobe"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.CIDR})
    consumes: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})
    produces: frozenset[AssetType] = frozenset({AssetType.LIVE_HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # -prefer-https was removed in httprobe v0.2+; probe HTTPS explicitly via -p
        cmd = ["httprobe", "-c", "20", "-p", "https:443"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            findings.append(
                Finding(
                    title=f"Live host: {url}",
                    severity=Severity.INFO,
                    description=f"HTTP/HTTPS service confirmed alive: {url}",
                    tool=self.name,
                    target=target,
                    raw={"url": url},
                )
            )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.LIVE_HOST, value=f.raw["url"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("url", "").startswith("http")
        ]

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=target + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            findings = self.parse_output(proc.stdout, target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
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
                error="Binary not found: httprobe",
            )
