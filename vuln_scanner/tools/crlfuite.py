"""crlfuzz — CRLF injection vulnerability scanner (Go binary from hahwul/crlfuzz)."""
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

# crlfuzz prints vulnerable URLs to stdout, one per line, prefixed with [+] or 🕵
_VULN_RE = re.compile(r"(?:\[\+\]|🕵|VULN|Found)[^\n]*(https?://\S+)", re.IGNORECASE)
_URL_RE = re.compile(r"(https?://\S+)")


class CRLFsuiteTool(AbstractTool):
    name: str = "crlfuite"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["crlfuzz", "-u", url, "-s"]
        if scan_input.proxy:
            cmd += ["-x", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if not m:
                # Also catch bare URL lines (crlfuzz outputs injected URL on success)
                m2 = _URL_RE.search(line)
                if m2 and ("%0d%0a" in line.lower() or "%0a" in line.lower() or
                           "crlfound" in line.lower()):
                    url = m2.group(1)
                    if url not in seen:
                        seen.add(url)
                        findings.append(Finding(
                            title=f"CRLF Injection: {url[:80]}",
                            severity=Severity.MEDIUM,
                            description=f"crlfuzz detected CRLF injection at: {url}",
                            tool=self.name, target=target, cwe=["CWE-93"],
                            raw={"line": line},
                        ))
                continue
            url = m.group(1)
            if url not in seen:
                seen.add(url)
                findings.append(Finding(
                    title=f"CRLF Injection: {url[:80]}",
                    severity=Severity.MEDIUM,
                    description=f"crlfuzz detected CRLF injection at: {url}",
                    tool=self.name, target=target, cwe=["CWE-93"],
                    raw={"line": line},
                ))
        return findings
