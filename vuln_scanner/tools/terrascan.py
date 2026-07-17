import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class TerrascanTool(AbstractTool):
    name: str = "terrascan"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "terrascan", "scan",
            "-d", target,
            "-o", "json",
            "--non-recursive" if scan_input.mode in ("paranoid", "passive") else "",
        ]
        cmd = [c for c in cmd if c]  # remove empty strings
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
        results = data.get("results", data)
        violations = results.get("violations", []) if isinstance(results, dict) else []

        for v in violations:
            sev = _parse_severity(v.get("severity", "medium"))
            resource = v.get("resource_name", target)
            rule_name = v.get("rule_name", "")
            description = v.get("description", rule_name)
            category = v.get("category", "")

            findings.append(Finding(
                title=f"{rule_name}: {resource}" if rule_name else description[:80],
                severity=sev,
                description=(
                    f"{description}\n"
                    f"Resource: {resource}\n"
                    f"File: {v.get('file', '')}"
                    + (f"\nCategory: {category}" if category else "")
                ),
                tool=self.name,
                target=target,
                references=[v.get("rule_reference_id", "")],
                raw=v,
            ))
        return findings
