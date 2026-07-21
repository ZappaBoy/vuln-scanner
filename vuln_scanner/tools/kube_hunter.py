"""kube-hunter — active Kubernetes penetration testing tool."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
}


class KubeHunterTool(AbstractTool):
    name: str = "kube-hunter"
    binary: str = "kube-hunter"
    category: str = "cloud"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.HOST, TargetType.IP, TargetType.CLOUD,
    })

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = re.sub(r"^https?://", "", target).rstrip("/")
        cmd = [
            "kube-hunter",
            "--remote", host,
            "--report", "json",
        ]
        if scan_input.mode in ("active", "aggressive"):
            cmd.append("--active")
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        # kube-hunter wraps JSON in surrounding text; extract the JSON block
        json_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not json_match:
            return []

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for vuln in data.get("vulnerabilities", []):
            name = vuln.get("vulnerability", vuln.get("name", "Unknown"))
            description = vuln.get("description", "")
            evidence = vuln.get("evidence", "")
            location = vuln.get("location", target)
            sev_str = vuln.get("severity", "medium").lower()
            sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
            vid = vuln.get("vid", vuln.get("id", ""))

            findings.append(Finding(
                title=f"kube-hunter [{vid}]: {name}",
                severity=sev,
                description=(
                    f"{description}\n\nLocation: {location}"
                    + (f"\nEvidence: {evidence}" if evidence else "")
                ).strip(),
                tool=self.name,
                target=target,
                raw=vuln,
            ))

        return findings
