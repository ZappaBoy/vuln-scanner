"""SSTImap — SSTI detection with interactive exploitation interface."""

import re

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_ENGINE_RE = re.compile(r"is vulnerable to SSTI with (?:engine\s+)?([^\n\r]+)", re.IGNORECASE)
_INJECT_RE = re.compile(r"injectable parameter[:\s]+([^\n\r]+)", re.IGNORECASE)


class SSTImapTool(AbstractTool):
    name: str = "sstimap"
    binary: str = "python3"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        level = {
            ScanMode.AGGRESSIVE: "5",
            ScanMode.ACTIVE: "3",
            ScanMode.PASSIVE: "1",
            ScanMode.PARANOID: "1",
        }.get(scan_input.mode, "2")
        cmd = [
            "python3",
            "/opt/SSTImap/sstimap.py",
            "-u",
            url,
            "--level",
            level,
            "--no-color",
        ]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _ENGINE_RE.finditer(raw):
            engine = m.group(1).strip().rstrip(".")
            findings.append(
                Finding(
                    title=f"SSTI via {engine} template engine",
                    severity=Severity.CRITICAL,
                    description=(
                        f"SSTImap confirmed Server-Side Template Injection (SSTI) using the {engine} engine on {target}. "
                        "This may allow remote code execution."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-94"],
                    raw={"engine": engine},
                )
            )
        return findings
