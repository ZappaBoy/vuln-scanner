"""Dirsearch — web path/directory brute-force scanner."""
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_LINE_RE = re.compile(r"(\d{3})\s+\d+\S*\s+(https?://\S+)")


class DirsearchTool(AbstractTool):
    name: str = "dirsearch"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})
    silent_flags: list[str] = ["--quiet"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        threads = "50" if scan_input.mode == ScanMode.AGGRESSIVE else "20"
        cmd = ["dirsearch", "-u", url, "-t", threads, "--format", "plain", "--quiet", "--no-color"]
        if scan_input.mode in (ScanMode.PASSIVE, ScanMode.PARANOID):
            cmd += ["--extensions", "php,html,txt,json,xml"]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _LINE_RE.search(line)
            if not m:
                continue
            status, url = m.group(1), m.group(2)
            if url in seen:
                continue
            seen.add(url)
            if status.startswith("2"):
                sev = Severity.INFO
            elif status in ("401", "403"):
                sev = Severity.LOW
            else:
                continue
            findings.append(Finding(
                title=f"Found path [{status}]: {url}",
                severity=sev,
                description=f"Dirsearch found accessible path: {url} (HTTP {status})",
                tool=self.name,
                target=target,
                cwe=["CWE-538"],
                raw={"status": status, "url": url},
            ))
        return findings
