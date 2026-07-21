"""CycloneDX CLI — SBOM generation and analysis."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class CycloneDXTool(AbstractTool):
    name: str = "cyclonedx"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.IMAGE})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "cyclonedx", "analyze",
            "--input-format", "auto",
            "--input-file", target,
            "--output-format", "json",
            "--output-file", OUTPUT_FILE_SENTINEL,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            components = data.get("components", [])
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                affects = vuln.get("affects", [])
                ratings = vuln.get("ratings", [{}])
                sev_str = ratings[0].get("severity", "medium").lower() if ratings else "medium"
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                sev = sev_map.get(sev_str, Severity.MEDIUM)
                vuln_id = vuln.get("id", "")
                desc = vuln.get("description", vuln_id)
                findings.append(Finding(
                    title=f"CycloneDX [{vuln_id}]: {desc[:60]}",
                    severity=sev,
                    description=desc,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    cve=[vuln_id] if vuln_id.startswith("CVE-") else [],
                    raw=vuln,
                ))
            if not vulns:
                findings.append(Finding(
                    title=f"SBOM generated: {len(components)} components",
                    severity=Severity.INFO,
                    description=f"CycloneDX generated SBOM with {len(components)} components",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"components": len(components)},
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
