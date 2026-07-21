"""ROADrecon — Azure AD and Entra ID reconnaissance."""
import json
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_PRIV_RE = re.compile(r"(?:privileged|global admin|admin role)[^\n]+", re.IGNORECASE)
_GUEST_RE = re.compile(r"guest[^\n]+", re.IGNORECASE)


class ROADreconTool(AbstractTool):
    name: str = "roadrecon"
    binary: str = "roadrecon"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            # Flag privileged users
            for user in data.get("users", []):
                roles = user.get("roles", [])
                if any("admin" in r.lower() or "global" in r.lower() for r in roles):
                    upn = user.get("userPrincipalName", "")
                    findings.append(Finding(
                        title=f"Azure AD privileged user: {upn}",
                        severity=Severity.MEDIUM,
                        description=f"User {upn} has admin roles: {', '.join(roles)}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-284"],
                        raw=user,
                    ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            # roadrecon gather then dump
            gather_cmd = ["roadrecon", "gather"]
            if scan_input.auth.bearer_token:
                gather_cmd += ["--access-token", scan_input.auth.bearer_token]
            subprocess.run(gather_cmd, capture_output=True, text=True,
                          timeout=scan_input.timeout // 2)
            dump_proc = subprocess.run(
                ["roadrecon", "dump", "--users", "--groups", "--apps", "--json"],
                capture_output=True, text=True, timeout=scan_input.timeout // 2,
            )
            duration = time.monotonic() - start
            raw = dump_proc.stdout + dump_proc.stderr
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
                              status=ScanStatus.FAILED, error="Binary not found: roadrecon")
