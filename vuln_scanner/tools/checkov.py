import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--check", "HIGH,CRITICAL"],
    ScanMode.PASSIVE:  ["--check", "HIGH,CRITICAL"],
    ScanMode.ACTIVE:   [],
    ScanMode.AGGRESSIVE: ["--enable-secret-scan-all-files"],
}


class CheckovTool(AbstractTool):
    name: str = "checkov"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "."
        cmd = ["checkov", "-d", path, "-o", "json", "--quiet", "--compact"]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        # checkov may output multiple JSON objects (one per framework); wrap in array if needed
        raw = raw.strip()
        if not raw:
            return []

        results_list: list[dict] = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                results_list = parsed
            elif isinstance(parsed, dict):
                results_list = [parsed]
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for block in results_list:
            for check in block.get("results", {}).get("failed_checks", []):
                result = check.get("check_result", {})
                check_type = block.get("check_type", "")
                sev_label = check.get("severity") or "medium"
                severity = _parse_severity(sev_label)
                filepath = check.get("repo_file_path") or check.get("file_path", target)
                line_range = check.get("file_line_range", [])
                line_info = f":{line_range[0]}" if line_range else ""
                cks = result.get("check_id", check.get("check_id", "?"))
                findings.append(Finding(
                    title=f"[{cks}] {check.get('check', {}).get('name', 'IaC check failed')}",
                    severity=severity,
                    description=(
                        f"{check.get('check', {}).get('name', '')}\n"
                        f"File: {filepath}{line_info}\n"
                        f"Framework: {check_type}\n"
                        f"Resource: {check.get('resource', '')}"
                    ),
                    tool=self.name,
                    target=filepath,
                    references=check.get("check", {}).get("guide_link", []),
                    raw=check,
                ))
        return findings
