import json
import os

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--strict"],
    ScanMode.PASSIVE:  [],
    ScanMode.ACTIVE:   [],
    ScanMode.AGGRESSIVE: ["--strict", "--fix"],
}


class PipAuditTool(AbstractTool):
    name: str = "pip-audit"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["pip-audit", "-f", "json", "-l"]

        # If target looks like a requirements file, use it; else scan environment
        req_candidates = [
            os.path.join(target, "requirements.txt"),
            os.path.join(target, "requirements/base.txt"),
            target,
        ] if not target.endswith(".txt") else [target]

        req_file = next((p for p in req_candidates if os.path.isfile(p)), None)
        if req_file:
            cmd += ["-r", req_file]

        cmd += _MODE_FLAGS.get(scan_input.mode, [])
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
        for dep in data.get("dependencies", []):
            pkg = dep.get("name", "?")
            version = dep.get("version", "?")
            for vuln in dep.get("vulns", []):
                vid = vuln.get("id", "")
                fix_versions = vuln.get("fix_versions", [])
                aliases = vuln.get("aliases", [])
                cves = [a for a in aliases if a.startswith("CVE-")]
                findings.append(Finding(
                    title=f"{vid} in {pkg} {version}",
                    severity=Severity.HIGH,
                    description=(
                        f"Package: {pkg} {version}\n"
                        f"Vulnerability: {vid}\n"
                        f"Description: {vuln.get('description', '')}\n"
                        f"Fix: {', '.join(fix_versions) if fix_versions else 'no fix available'}"
                    ),
                    tool=self.name,
                    target=target,
                    cve=cves if cves else ([vid] if vid.startswith("CVE-") else []),
                    references=vuln.get("fix_versions", []),
                    raw=vuln,
                ))
        return findings
