"""Hydra — brute-force login tool (SSH, FTP, HTTP-form, HTTP-get, ...)."""
import re
import tempfile
import os

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# Credential lists embedded so we don't depend on host wordlist paths.
_USERNAMES = ["admin", "root", "user", "test", "administrator", "guest", "ubuntu", "pi", "deploy"]
_PASSWORDS_PARANOID = ["admin", "root", "password", "123456", "pass", "guest", "changeme"]
_PASSWORDS_ACTIVE = _PASSWORDS_PARANOID + [
    "password123", "1234", "12345", "letmein", "qwerty", "abc123",
    "welcome", "monkey", "dragon", "master", "1q2w3e", "iloveyou",
]
_PASSWORDS_AGGRESSIVE = _PASSWORDS_ACTIVE + [
    "admin123", "root123", "test123", "pass123", "access", "login",
    "secret", "shadow", "super", "enable", "cisco", "default", "toor",
    "system", "manager", "service", "backup", "oracle", "postgres",
]

# "host: 10.0.0.1   login: admin   password: 1234" (hydra -o format)
_RESULT_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)"
    r"\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)"
)


class HydraTool(AbstractTool):
    name: str = "hydra"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Service defaults to ssh; override via extra_args e.g. "--service ftp"
        # We write temp wordlist files and pass them with -L / -P
        return []  # actual command built in run() due to temp file management

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _RESULT_RE.search(line)
            if not m:
                continue
            service = m.group("service")
            login = m.group("login")
            password = m.group("password")
            port = m.group("port")
            findings.append(Finding(
                title=f"Weak credentials on {service}/{port}: {login}:{password}",
                severity=Severity.CRITICAL,
                description=(
                    f"Hydra found valid credentials on {target}:{port} ({service}).\n"
                    f"Username: {login}\nPassword: {password}"
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-521"],
                raw={"service": service, "port": port, "login": login, "password": password},
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        import subprocess, time
        from vuln_scanner.tools.models import ScanResult
        from vuln_scanner.tools.enums import ScanStatus

        mode = scan_input.mode
        passwords = (
            _PASSWORDS_AGGRESSIVE if mode == ScanMode.AGGRESSIVE
            else _PASSWORDS_ACTIVE if mode == ScanMode.ACTIVE
            else _PASSWORDS_PARANOID
        )
        auth = scan_input.auth
        usernames = [auth.username] if auth.username else _USERNAMES
        pw_list = [auth.password] if auth.password else passwords

        fd_u, user_file = tempfile.mkstemp(prefix="vs_hydra_u_", suffix=".txt")
        fd_p, pass_file = tempfile.mkstemp(prefix="vs_hydra_p_", suffix=".txt")
        try:
            with os.fdopen(fd_u, "w") as f:
                f.write("\n".join(usernames) + "\n")
            with os.fdopen(fd_p, "w") as f:
                f.write("\n".join(pw_list) + "\n")

            # Default to ssh; caller can override via extra_args
            service = "ssh"
            extra = list(scan_input.extra_args)
            if "--service" in extra:
                idx = extra.index("--service")
                service = extra.pop(idx + 1)
                extra.pop(idx)

            cmd = [
                "hydra", "-L", user_file, "-P", pass_file,
                "-t", "4", "-q",
                target, service,
            ] + extra

            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=scan_input.timeout
                )
                duration = time.monotonic() - start
                raw = proc.stdout + proc.stderr
                findings = self.parse_output(raw, target)
                return ScanResult(
                    tool=self.name, target=target, findings=findings,
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
                    status=ScanStatus.FAILED, error="Binary not found: hydra",
                )
        finally:
            for f in (user_file, pass_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass
