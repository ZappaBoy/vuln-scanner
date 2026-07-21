"""Kubescape — Kubernetes security posture scanner (NSA/MITRE frameworks)."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class KubescapeTool(AbstractTool):
    name: str = "kubescape"
    binary: str = "kubescape"
    category: str = "cloud"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "kubescape", "scan",
            "--format", "json",
            "--output", OUTPUT_FILE_SENTINEL,
            "--verbose",
        ]
        # If target is a file/directory, scan it; otherwise scan the cluster
        import os
        if os.path.exists(target):
            cmd.append(target)
        # else: scan the current cluster context (no extra arg needed)
        cmd += scan_input.extra_args
        return cmd

    def run(self, target: str, scan_input: ScanInput) -> "ScanResult":  # type: ignore[name-defined]
        return self._run_with_tempfile(target, scan_input, suffix=".json")

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        results = data.get("results", [])
        for control in results:
            status = control.get("status", {}).get("status", "")
            if status in ("passed", "skipped"):
                continue

            name = control.get("name", "Unknown control")
            sev_str = control.get("severity", {})
            if isinstance(sev_str, dict):
                sev_str = sev_str.get("severity", "medium")
            sev = _SEV_MAP.get(str(sev_str).lower(), Severity.MEDIUM)
            description = control.get("description", "")
            remediation = control.get("remediation", "")
            control_id = control.get("controlID", "")

            # Collect affected resources
            resources = []
            for rs in control.get("resources", []):
                obj = rs.get("object", {})
                kind = obj.get("kind", "")
                meta = obj.get("metadata", {})
                ns = meta.get("namespace", "")
                res_name = meta.get("name", "")
                if kind and res_name:
                    resources.append(f"{kind}/{ns}/{res_name}" if ns else f"{kind}/{res_name}")

            resource_str = ", ".join(resources[:10])
            if len(resources) > 10:
                resource_str += f" (+{len(resources) - 10} more)"

            findings.append(Finding(
                title=f"Kubescape [{control_id}]: {name}",
                severity=sev,
                description=(
                    f"{description}\n\n"
                    f"Affected resources: {resource_str or 'N/A'}\n\n"
                    f"Remediation: {remediation}"
                ).strip(),
                tool=self.name,
                target=target,
                raw={"control_id": control_id, "name": name, "affected": resources},
            ))

        return findings
