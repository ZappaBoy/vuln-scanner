"""License Finder — OSS license compliance scanner."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_COPYLEFT = {"GPL", "AGPL", "LGPL", "MPL", "EUPL", "CDDL", "CPL", "EPL"}
_LINE_RE = re.compile(r"(\S+)\s+([\d.]+)\s+(.+)")


class LicenseFinderTool(AbstractTool):
    name: str = "license-finder"
    binary: str = "license_finder"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["license_finder", "report", "--format", "text", "--project-path", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            pkg, version, license_str = m.group(1), m.group(2), m.group(3).strip()
            # Flag unapproved or copyleft licenses
            is_copyleft = any(cl in license_str.upper() for cl in _COPYLEFT)
            if is_copyleft:
                findings.append(Finding(
                    title=f"Copyleft license: {pkg} {version} ({license_str})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Package {pkg} {version} uses {license_str} which may impose "
                        "distribution and source-sharing obligations."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"package": pkg, "version": version, "license": license_str},
                ))
        return findings
