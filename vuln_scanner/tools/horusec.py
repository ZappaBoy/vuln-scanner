import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class HorusecTool(AbstractTool):
    name: str = "horusec"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "horusec", "start",
            "-p", target,
            "-o", "json",
            "--disable-docker", "true",
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
        analysis = data.get("analysisVulnerabilities", [])
        for item in analysis:
            vuln = item.get("vulnerabilities", item)
            sev = _parse_severity(vuln.get("severity", "medium"))
            title = vuln.get("details", vuln.get("vulnHash", "Horusec finding"))[:80]
            filename = vuln.get("file", target)
            line = vuln.get("line", "")
            code = vuln.get("code", "")
            security_tool = vuln.get("securityTool", "")

            findings.append(Finding(
                title=title,
                severity=sev,
                description=(
                    f"{title}\n"
                    f"File: {filename}" + (f"\nLine: {line}" if line else "")
                    + (f"\nCode: {code[:200]}" if code else "")
                    + (f"\nDetected by: {security_tool}" if security_tool else "")
                ),
                tool=self.name,
                target=target,
                cwe=([f"CWE-{vuln['cwe']}"] if vuln.get("cwe") else []),
                raw=vuln,
            ))
        return findings
