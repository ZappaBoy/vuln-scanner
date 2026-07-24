"""dnsgen — powerful DNS name permutation and mutation tool."""

import subprocess
import time

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class DNSgenTool(AbstractTool):
    name: str = "dnsgen"
    binary: str = "dnsgen"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    consumes: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            perm = line.strip().lower()
            if perm and perm not in seen and "." in perm:
                seen.add(perm)
                findings.append(
                    Finding(
                        title=f"DNS mutation: {perm}",
                        severity=Severity.INFO,
                        description=f"dnsgen generated: {perm}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"permutation": perm},
                    )
                )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["permutation"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("permutation")
        ]

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["dnsgen", "-"],
                input=target + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout
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
                tool=self.name, target=target, duration=0.0, status=ScanStatus.FAILED, error="Binary not found: dnsgen"
            )
