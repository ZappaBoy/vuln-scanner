import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class OSVScannerTool(AbstractTool):
    name: str = "osv-scanner"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["osv-scanner", "--format", "json", "--recursive", target]
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
        for result in data.get("results", []):
            source = result.get("source", {}).get("path", target)
            for pkg in result.get("packages", []):
                pkg_name = pkg.get("package", {}).get("name", "unknown")
                pkg_version = pkg.get("package", {}).get("version", "")
                for vuln in pkg.get("vulnerabilities", []):
                    vid = vuln.get("id", "")
                    summary = vuln.get("summary", vid)
                    severity_raw = vuln.get("database_specific", {}).get("severity", "medium")
                    sev = _parse_severity(severity_raw)
                    cve = [a.get("id") for a in vuln.get("aliases", []) if a.get("id", "").startswith("CVE")]
                    refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

                    findings.append(Finding(
                        title=f"{pkg_name}@{pkg_version}: {vid}",
                        severity=sev,
                        description=(
                            f"{summary}\n"
                            f"Package: {pkg_name} {pkg_version}\n"
                            f"Source: {source}"
                        ),
                        tool=self.name,
                        target=target,
                        cve=cve,
                        references=refs[:5],
                        raw=vuln,
                    ))
        return findings
