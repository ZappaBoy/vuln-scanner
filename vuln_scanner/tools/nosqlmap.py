import re
from urllib.parse import urlparse

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_VULN_RE = re.compile(
    r"(?:vulnerable|injection|bypass|found|detected).+?(?:NoSQL|MongoDB|CouchDB|injection)",
    re.IGNORECASE,
)
_PARAM_RE = re.compile(r"parameter[:\s'\"]+([^\s'\"]+)", re.IGNORECASE)
_AUTH_RE = re.compile(r"authentication bypass", re.IGNORECASE)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class NoSQLMapTool(AbstractTool):
    name: str = "nosqlmap"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            attack = "1"  # app-level injection only
        else:
            attack = "2"  # app-level + DB-level injection

        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        port = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")
        cmd = ["nosqlmap", "--attack", attack, "--victim", host, "--webPort", port]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        clean = _ANSI_RE.sub("", raw)
        seen: set[str] = set()

        for line in clean.splitlines():
            line = line.strip()
            if not line:
                continue

            if _AUTH_RE.search(line):
                key = "auth_bypass"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title="NoSQL authentication bypass",
                        severity=Severity.CRITICAL,
                        description=f"NoSQL authentication bypass detected on {target}: {line}",
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line},
                    ))
                continue

            if _VULN_RE.search(line):
                key = line
                if key not in seen:
                    seen.add(key)
                    param_m = _PARAM_RE.search(line)
                    param = param_m.group(1) if param_m else ""
                    findings.append(Finding(
                        title=f"NoSQL injection" + (f" — parameter '{param}'" if param else ""),
                        severity=Severity.HIGH,
                        description=f"NoSQL injection detected on {target}: {line}",
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line, "param": param},
                    ))

        return findings
