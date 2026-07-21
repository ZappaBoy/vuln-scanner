import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class NpmAuditTool(AbstractTool):
    name: str = "npm-audit"
    binary: str = "npm"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["npm", "audit", "--json", "--prefix", target]
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

        # npm audit v7+ format
        vulns = data.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity_raw = info.get("severity", "medium")
            sev = _parse_severity(severity_raw)
            via = info.get("via", [])
            cve: list[str] = []
            refs: list[str] = []
            for v in via:
                if isinstance(v, dict):
                    url = v.get("url", "")
                    if url:
                        refs.append(url)
                    cve_ids = v.get("cves", [])
                    cve.extend(cve_ids)

            findings.append(Finding(
                title=f"{pkg_name}: {severity_raw.upper()} vulnerability",
                severity=sev,
                description=(
                    f"Vulnerable package: {pkg_name}\n"
                    f"Range: {info.get('range', 'unknown')}\n"
                    f"Fix available: {info.get('fixAvailable', False)}"
                ),
                tool=self.name,
                target=target,
                cve=cve,
                references=refs[:5],
                raw=info,
            ))

        return findings
