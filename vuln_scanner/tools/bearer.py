import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class BearerTool(AbstractTool):
    name: str = "bearer"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "bearer", "scan", target,
            "--format", "json",
            "--quiet",
        ]
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
        for severity_bucket in ("critical", "high", "medium", "low", "warning"):
            for item in data.get(severity_bucket, []):
                sev = _parse_severity(severity_bucket)
                title = item.get("id", item.get("title", "Bearer finding"))
                description = item.get("description", "")
                line = item.get("line_number", "")
                filename = item.get("filename", target)
                cwe = item.get("cwe_ids", [])

                findings.append(Finding(
                    title=f"{title}: {filename}",
                    severity=sev,
                    description=(
                        f"{description}\n"
                        f"File: {filename}" + (f"\nLine: {line}" if line else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=[f"CWE-{c}" for c in cwe],
                    raw=item,
                ))
        return findings
