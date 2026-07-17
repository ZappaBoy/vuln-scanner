import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class KubeBenchTool(AbstractTool):
    name: str = "kube-bench"
    category: str = "cloud"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["kube-bench", "--json"]
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
        for control in data.get("Controls", []):
            for test_group in control.get("tests", []):
                for result in test_group.get("results", []):
                    if result.get("status") in ("PASS", "INFO"):
                        continue
                    status = result.get("status", "FAIL")
                    sev = Severity.HIGH if status == "FAIL" else Severity.MEDIUM
                    findings.append(Finding(
                        title=result.get("test_desc", "Kubernetes benchmark failure"),
                        severity=sev,
                        description=(
                            f"CIS Benchmark: {control.get('text', '')} — "
                            f"{result.get('test_desc', '')}\n"
                            f"Remediation: {result.get('remediation', 'See CIS Kubernetes Benchmark')}"
                        ),
                        tool=self.name,
                        target=target,
                        raw=result,
                    ))
        return findings
