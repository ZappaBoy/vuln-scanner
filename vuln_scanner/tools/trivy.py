import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_SCANNERS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "vuln",
    ScanMode.PASSIVE:    "vuln",
    ScanMode.ACTIVE:     "vuln,config,secret",
    ScanMode.AGGRESSIVE: "vuln,config,secret,license",
}


class TrivyTool(AbstractTool):
    name: str = "trivy"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IMAGE, TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        scanners = _MODE_SCANNERS.get(scan_input.mode, "vuln")
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--quiet",
            "--scanners", scanners,
            "--timeout", f"{scan_input.timeout}s",
        ]
        cmd += scan_input.extra_args
        cmd.append(target)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for result in data.get("Results", []):
            scan_target = result.get("Target", target)

            for vuln in result.get("Vulnerabilities") or []:
                vid = vuln.get("VulnerabilityID", "")
                severity = _parse_severity(vuln.get("Severity", "unknown"))
                pkg = vuln.get("PkgName", "?")
                installed = vuln.get("InstalledVersion", "?")
                fixed = vuln.get("FixedVersion", "not fixed")
                findings.append(Finding(
                    title=f"{vid} in {pkg} {installed}",
                    severity=severity,
                    description=(
                        f"{vuln.get('Title', vuln.get('Description', ''))}\n"
                        f"Package: {pkg} {installed} → fix: {fixed}"
                    ),
                    tool=self.name,
                    target=scan_target,
                    cve=[vid] if vid.startswith("CVE-") else [],
                    references=vuln.get("References", []),
                    raw=vuln,
                ))

            for misconfig in result.get("Misconfigurations") or []:
                severity = _parse_severity(misconfig.get("Severity", "low"))
                findings.append(Finding(
                    title=misconfig.get("Title", "Misconfiguration"),
                    severity=severity,
                    description=misconfig.get("Description", "")
                                + "\n" + misconfig.get("Resolution", ""),
                    tool=self.name,
                    target=scan_target,
                    references=[misconfig.get("PrimaryURL", "")],
                    raw=misconfig,
                ))

        return findings
