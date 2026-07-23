"""XSRFProbe — CSRF audit and exploitation tool."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_VULN_RE = re.compile(r"\[CRITICAL\].*?(?:CSRF|XSRF)[^\n]*", re.IGNORECASE)
_ENDPOINT_RE = re.compile(r"Endpoint[:\s]+(https?://\S+)", re.IGNORECASE)
_FORM_RE = re.compile(r"Form[:\s#]+([^\n]+)", re.IGNORECASE)


class XSRFProbeTool(AbstractTool):
    name: str = "xsrfprobe"
    binary: str = "xsrfprobe"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["xsrfprobe", "-u", url, "--no-prompt"]
        if scan_input.auth.cookie_string:
            cmd += ["--cookie", scan_input.auth.cookie_string]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if re.search(r"\[CRITICAL\].*(?:CSRF|XSRF|No token)", line, re.IGNORECASE):
                ep_m = _ENDPOINT_RE.search(line)
                endpoint = ep_m.group(1) if ep_m else target
                findings.append(
                    Finding(
                        title=f"CSRF vulnerability: {endpoint}",
                        severity=Severity.HIGH,
                        description=f"XSRFProbe detected missing or bypassable CSRF protection on {endpoint}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-352"],
                        raw={"line": line},
                    )
                )
            elif re.search(r"(?:token not found|csrf not found)", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"Missing CSRF token on {target}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-352"],
                        raw={"line": line},
                    )
                )
        return findings
