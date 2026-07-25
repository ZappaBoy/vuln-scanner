"""kubeaudit — Kubernetes RBAC and security audit."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.INFO, "debug": Severity.INFO}


class KubeauditTool(AbstractTool):
    name: str = "kubeaudit"
    binary: str = "kubeaudit"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # kubeaudit emits NDJSON by default; no format flag needed.
        cmd = ["kubeaudit", "all"]
        if target != "cluster":
            cmd += ["--manifest", target]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                level = obj.get("level", "info").lower()
                if level in ("info", "debug"):
                    continue
                sev = _SEV_MAP.get(level, Severity.MEDIUM)
                audit_id = obj.get("AuditResultName", "")
                msg = obj.get("msg", "")
                resource = obj.get("ResourceKind", "")
                name = obj.get("ResourceName", "")
                findings.append(
                    Finding(
                        title=f"kubeaudit [{level.upper()}] {audit_id}",
                        severity=sev,
                        description=(f"{msg}\nResource: {resource}/{name}" if resource else msg),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-284"],
                        raw=obj,
                    )
                )
            except json.JSONDecodeError:
                continue
        return findings
