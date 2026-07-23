"""Binwalk — firmware extraction and vulnerability analysis."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_FOUND_RE = re.compile(r"(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)")
_DANGEROUS = re.compile(
    r"(?:Private key|Certificate|Password|Secret|SSH|Key|SSL|Credential|\.pem|\.key)",
    re.IGNORECASE,
)
_EXECUTABLE = re.compile(r"(?:ELF|executable|Linux|busybox|uImage)", re.IGNORECASE)


class BinwalkTool(AbstractTool):
    name: str = "binwalk"
    binary: str = "binwalk"
    category: str = "binary"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["binwalk", "--entropy", "--signature", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _FOUND_RE.match(line.strip())
            if not m:
                continue
            offset, description = m.group(1), m.group(2).strip()
            key = description[:40]
            if key in seen:
                continue
            seen.add(key)
            if _DANGEROUS.search(description):
                sev = Severity.HIGH
                findings.append(
                    Finding(
                        title=f"Sensitive data in firmware: {description[:60]}",
                        severity=sev,
                        description=f"binwalk found sensitive data at offset {offset}: {description}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-312"],
                        raw={"offset": offset, "description": description},
                    )
                )
            elif _EXECUTABLE.search(description):
                findings.append(
                    Finding(
                        title=f"Embedded executable: {description[:60]}",
                        severity=Severity.INFO,
                        description=f"binwalk found embedded executable at offset {offset}: {description}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"offset": offset, "description": description},
                    )
                )
        return findings
