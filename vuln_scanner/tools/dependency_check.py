import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--enableExperimental"],
    ScanMode.PASSIVE:  [],
    ScanMode.ACTIVE:   ["--enableExperimental", "--enableRetired"],
    ScanMode.AGGRESSIVE: ["--enableExperimental", "--enableRetired",
                          "--analyzer", "all"],
}


class DependencyCheckTool(AbstractTool):
    name: str = "dependency-check"
    binary: str = "dependency-check"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "."
        cmd = [
            "dependency-check",
            "--project", "vuln-scanner-scan",
            "--scan", path,
            "--format", "JSON",
            "--out", OUTPUT_FILE_SENTINEL,
            "--noupdate",
        ]
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
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                vid = vuln.get("name", "")
                sev_label = vuln.get("severity", "unknown")
                severity = _parse_severity(sev_label)
                filepath = dep.get("filePath", target)
                pkg = dep.get("fileName", "?")
                refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]
                findings.append(Finding(
                    title=f"{vid} in {pkg}",
                    severity=severity,
                    description=(
                        vuln.get("description", "")
                        + f"\nFile: {filepath}"
                    ),
                    tool=self.name,
                    target=filepath,
                    cve=[vid] if vid.startswith("CVE-") else [],
                    references=refs,
                    raw=vuln,
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
