import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class GovulncheckTool(AbstractTool):
    name: str = "govulncheck"
    binary: str = "govulncheck"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["govulncheck", "-json", "./..."]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            vuln = item.get("vuln")
            if not vuln:
                continue

            osv_id = vuln.get("id", "")
            summary = vuln.get("summary", osv_id)
            aliases = vuln.get("aliases", [])
            cve = [a for a in aliases if a.startswith("CVE")]
            refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

            modules = vuln.get("modules", [])
            for mod in modules:
                pkg_path = mod.get("path", "")
                findings.append(
                    Finding(
                        title=f"{pkg_path}: {osv_id}" if pkg_path else summary[:80],
                        severity=Severity.HIGH,
                        description=f"{summary}\nModule: {pkg_path}",
                        tool=self.name,
                        target=target,
                        cve=cve,
                        references=refs[:5],
                        raw=vuln,
                    )
                )

        return findings
