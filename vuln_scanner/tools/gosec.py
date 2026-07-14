import json

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    Severity,
    _parse_severity,
)

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["-severity", "high", "-confidence", "high"],
    ScanMode.PASSIVE:  ["-severity", "medium"],
    ScanMode.ACTIVE:   [],
    ScanMode.AGGRESSIVE: ["-tests"],
}


class GosecTool(AbstractTool):
    name: str = "gosec"
    category: str = "sast"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "./..."
        if not path.endswith("/...") and not path.endswith(".go"):
            path = path.rstrip("/") + "/..."
        cmd = ["gosec", "-fmt", "json", "-quiet"]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        cmd.append(path)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for issue in data.get("Issues", []):
            severity = _parse_severity(issue.get("severity", "medium"))
            filepath = issue.get("file", target)
            line = issue.get("line", "?")
            rule_id = issue.get("rule_id", "?")
            cwe = issue.get("cwe", {})
            cwe_id = cwe.get("id", "")
            cwe_url = cwe.get("url", "")
            findings.append(Finding(
                title=f"[{rule_id}] {issue.get('details', 'gosec finding')[:100]}",
                severity=severity,
                description=(
                    f"{issue.get('details', '')}\n"
                    f"File: {filepath}:{line}\n"
                    f"CWE: {cwe_id}"
                ),
                tool=self.name,
                target=filepath,
                references=[cwe_url] if cwe_url else [],
                raw=issue,
            ))
        return findings
