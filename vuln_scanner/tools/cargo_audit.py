"""cargo-audit — Rust crates vulnerability scanner."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "none": Severity.INFO}


class CargoAuditTool(AbstractTool):
    name: str = "cargo-audit"
    binary: str = "cargo-audit"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["cargo-audit", "--json", "--file", f"{target}/Cargo.lock"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", {}).get("list", []):
                advisory = vuln.get("advisory", {})
                pkg = vuln.get("package", {})
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                title = advisory.get("title", "")
                sev_str = advisory.get("severity", "medium").lower()
                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                cves = advisory.get("aliases", [])
                findings.append(Finding(
                    title=f"cargo-audit [{name} {version}]: {title}",
                    severity=sev,
                    description=advisory.get("description", title),
                    tool=self.name,
                    target=target,
                    cwe=[],
                    cve=[c for c in cves if c.startswith("CVE-")],
                    raw=vuln,
                ))
        except json.JSONDecodeError:
            pass
        return findings
