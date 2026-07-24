import subprocess
import time

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class AlterxTool(AbstractTool):
    name: str = "alterx"
    binary: str = "alterx"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # alterx reads from stdin; see run()

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        cmd = ["alterx", "-enrich", "-silent"] + scan_input.extra_args
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=domain + "\n",
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            return ScanResult(
                tool=self.name,
                target=target,
                findings=self.parse_output(proc.stdout, target),
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name, target=target, duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT, error=f"Timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error="Binary not found: alterx",
            )

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            subdomain = line.strip()
            if not subdomain or subdomain in seen:
                continue
            seen.add(subdomain)
            findings.append(
                Finding(
                    title=f"Permutation: {subdomain}",
                    severity=Severity.INFO,
                    description=f"Subdomain permutation generated: {subdomain}",
                    tool=self.name,
                    target=target,
                    raw={"subdomain": subdomain},
                )
            )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["subdomain"], source=self.name, target=result.target)
            for f in result.findings if f.raw.get("subdomain")
        ]
