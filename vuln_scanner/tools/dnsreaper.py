"""dnsReaper — subdomain takeover detection with 50+ provider fingerprints."""
import json
import subprocess
import time

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanStatus


class DnsReaperTool(AbstractTool):
    name: str = "dnsreaper"
    binary: str = "dnsreaper"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        import re
        domain = re.sub(r"^https?://", "", target).rstrip("/")
        cmd = ["dnsreaper", "single", "--target", domain, "--output", "json"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if not raw.strip():
            return findings

        # dnsReaper outputs a JSON array of vulnerable domains
        try:
            items = json.loads(raw)
            if not isinstance(items, list):
                items = [items]
        except json.JSONDecodeError:
            # Try JSONL
            items = []
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for item in items:
            domain = item.get("domain", target)
            provider = item.get("provider", "Unknown provider")
            confidence = item.get("confidence", "medium")
            signature = item.get("signature", "")
            sev = Severity.HIGH if confidence in ("high", "certain") else Severity.MEDIUM
            findings.append(Finding(
                title=f"Subdomain takeover: {domain} ({provider})",
                severity=sev,
                description=(
                    f"dnsReaper detected potential subdomain takeover for {domain}.\n"
                    f"Provider: {provider}\nConfidence: {confidence}"
                    + (f"\nSignature: {signature}" if signature else "")
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-350"],
                raw=item,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            return ScanResult(
                tool=self.name, target=target, findings=self.parse_output(proc.stdout, target),
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
                status=ScanStatus.FAILED, error="Binary not found: dnsreaper",
            )
