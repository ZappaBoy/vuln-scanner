"""KubeLinter — Kubernetes YAML linting."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"KubeLinterError": Severity.HIGH, "error": Severity.HIGH,
            "warning": Severity.MEDIUM, "info": Severity.INFO}


class KubeLinterTool(AbstractTool):
    name: str = "kube-linter"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["kube-linter", "lint", "--format", "json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for report in data.get("Reports", []):
                check = report.get("Check", "")
                diagnostic = report.get("Diagnostic", {})
                msg = diagnostic.get("Message", "")
                obj = report.get("Object", {}).get("K8sObject", {})
                resource = f"{obj.get('GroupVersionKind', {}).get('Kind', '')} {obj.get('Name', '')}"
                findings.append(Finding(
                    title=f"kube-linter [{check}]: {msg[:60]}",
                    severity=Severity.MEDIUM,
                    description=f"Check: {check}\n{msg}\nResource: {resource}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-284"],
                    raw=report,
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                if re.search(r"KubeLinterError|error|warning", line, re.IGNORECASE):
                    findings.append(Finding(
                        title=f"kube-linter: {line[:80]}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-284"],
                        raw={"line": line},
                    ))
        return findings
