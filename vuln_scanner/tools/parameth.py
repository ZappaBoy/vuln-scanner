"""Parameth — brute-discover hidden GET and POST parameters."""
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_FOUND_RE = re.compile(r"\[Found\]\s+(?:GET|POST)\s+param[:\s]+(\w+)", re.IGNORECASE)
_SIZE_RE = re.compile(r"size[:=\s]+(\d+)", re.IGNORECASE)
_INTERESTING = re.compile(
    r"(?:id|key|token|debug|admin|secret|pass|auth|redirect|callback|file|path|dir|cmd|exec)",
    re.IGNORECASE,
)


class ParamethTool(AbstractTool):
    name: str = "parameth"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        # parameth uses -u for URL and -t for threads; -p for params wordlist
        wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
        cmd = ["parameth", "-u", url, "-p", wordlist]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-t", "10"]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _FOUND_RE.search(line)
            if m:
                param = m.group(1)
                sev = Severity.MEDIUM if _INTERESTING.search(param) else Severity.LOW
                findings.append(Finding(
                    title=f"Hidden parameter discovered: '{param}'",
                    severity=sev,
                    description=f"Parameth found a hidden parameter '{param}' on {target}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-200"],
                    raw={"parameter": param, "line": line},
                ))
        return findings
