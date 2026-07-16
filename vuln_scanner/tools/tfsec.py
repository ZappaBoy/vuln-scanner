import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--minimum-severity", "HIGH"],
    ScanMode.PASSIVE:  ["--minimum-severity", "HIGH"],
    ScanMode.ACTIVE:   ["--minimum-severity", "LOW"],
    ScanMode.AGGRESSIVE: ["--minimum-severity", "LOW", "--include-ignored",
                          "--include-passed"],
}


class TfsecTool(AbstractTool):
    name: str = "tfsec"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "."
        cmd = ["tfsec", path, "--format", "json", "--no-color", "--soft-fail"]
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
        for r in data.get("results", []):
            sev_label = r.get("severity", "medium")
            severity = _parse_severity(sev_label)
            location = r.get("location", {})
            filepath = location.get("filename", target)
            line = location.get("start_line", "?")
            rule_id = r.get("rule_id") or r.get("long_id", "?")
            refs = [r.get("links", [""])[0]] if r.get("links") else []
            findings.append(Finding(
                title=f"[{rule_id}] {r.get('description', 'tfsec finding')[:100]}",
                severity=severity,
                description=(
                    f"{r.get('description', '')}\n"
                    f"Resolution: {r.get('resolution', '')}\n"
                    f"File: {filepath}:{line}"
                ),
                tool=self.name,
                target=filepath,
                references=refs,
                raw=r,
            ))
        return findings
