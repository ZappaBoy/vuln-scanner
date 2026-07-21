"""Medusa — parallel brute-force login tool."""
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_CREDS_RE = re.compile(
    r"ACCOUNT FOUND:\s*\[([^\]]+)\]\s*Host:\s*(\S+)\s*User:\s*(\S+)\s*Password:\s*(\S+)",
    re.IGNORECASE,
)

_USERS = ["admin", "root", "user", "test", "administrator", "guest"]
_PASS_PARANOID = ["admin", "root", "password", "123456", "changeme"]
_PASS_ACTIVE = _PASS_PARANOID + ["password123", "letmein", "qwerty", "abc123", "welcome"]
_PASS_AGGRESSIVE = _PASS_ACTIVE + [
    "admin123", "root123", "test123", "access", "default", "toor", "oracle",
]


class MedusaTool(AbstractTool):
    name: str = "medusa"
    binary: str = "medusa"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _CREDS_RE.finditer(raw):
            service, host, user, password = m.group(1), m.group(2), m.group(3), m.group(4)
            findings.append(Finding(
                title=f"Weak credentials on {service}: {user}:{password}",
                severity=Severity.CRITICAL,
                description=(
                    f"Medusa found valid credentials on {host} ({service}).\n"
                    f"Username: {user}\nPassword: {password}"
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-521"],
                raw={"service": service, "user": user, "password": password},
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        mode = scan_input.mode
        passwords = (
            _PASS_AGGRESSIVE if mode == ScanMode.AGGRESSIVE
            else _PASS_ACTIVE if mode == ScanMode.ACTIVE
            else _PASS_PARANOID
        )
        auth = scan_input.auth
        users = [auth.username] if auth.username else _USERS
        pwds = [auth.password] if auth.password else passwords

        fd_u, user_file = tempfile.mkstemp(prefix="vs_medusa_u_", suffix=".txt")
        fd_p, pass_file = tempfile.mkstemp(prefix="vs_medusa_p_", suffix=".txt")
        start = time.monotonic()
        try:
            with os.fdopen(fd_u, "w") as f:
                f.write("\n".join(users) + "\n")
            with os.fdopen(fd_p, "w") as f:
                f.write("\n".join(pwds) + "\n")
            cmd = [
                "medusa", "-h", target,
                "-U", user_file, "-P", pass_file,
                "-M", "ssh", "-t", "4",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
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
                              status=ScanStatus.FAILED, error="Binary not found: medusa")
        finally:
            for f in (user_file, pass_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass
