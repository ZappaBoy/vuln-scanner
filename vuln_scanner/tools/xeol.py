"""Xeol — end-of-life component detection."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class XeolTool(AbstractTool):
    name: str = "xeol"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.PATH, TargetType.IMAGE, TargetType.REPO,
    })

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["xeol", target, "--output", f"json={OUTPUT_FILE_SENTINEL}"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for match in data.get("matches", []):
                pkg = match.get("package", {})
                eol = match.get("cycle", {})
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                eol_date = eol.get("eol", "")
                latest = eol.get("latest", "")
                findings.append(Finding(
                    title=f"End-of-life component: {name} {version}",
                    severity=Severity.HIGH,
                    description=(
                        f"Package {name} {version} has reached end-of-life"
                        + (f" as of {eol_date}" if eol_date else "")
                        + (f". Latest: {latest}" if latest else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-1104"],
                    raw=match,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
