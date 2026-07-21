import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--only-fixed"],      # only report fixable vulns
    ScanMode.PASSIVE:  ["--only-fixed"],
    ScanMode.ACTIVE:   [],
    ScanMode.AGGRESSIVE: ["--add-cpes-if-none"],
}


class GrypeTool(AbstractTool):
    name: str = "grype"
    binary: str = "grype"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IMAGE, TargetType.PATH})
    silent_flags: list[str] = ["--quiet"]
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["grype", target, "-o", "json", "--quiet"]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            vid = vuln.get("id", "")
            severity = _parse_severity(vuln.get("severity", "unknown"))
            artifact = match.get("artifact", {})
            pkg = artifact.get("name", "?")
            version = artifact.get("version", "?")
            fix = vuln.get("fix", {}).get("versions", [])
            findings.append(Finding(
                title=f"{vid} in {pkg} {version}",
                severity=severity,
                description=(
                    f"{vuln.get('description', '')}\n"
                    f"Package: {pkg} {version}"
                    + (f" → fix: {', '.join(fix)}" if fix else " (no fix available)")
                ),
                tool=self.name,
                target=target,
                cve=[vid] if vid.startswith("CVE-") else [],
                references=vuln.get("urls", []),
                raw=match,
            ))
        return findings
