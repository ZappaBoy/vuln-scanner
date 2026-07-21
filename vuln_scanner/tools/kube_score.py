"""Kube-score — Kubernetes object static analysis."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_GRADE_MAP = {"CRITICAL": Severity.CRITICAL, "WARNING": Severity.MEDIUM,
              "OK": Severity.INFO, "SKIPPED": Severity.INFO}


class KubeScoreTool(AbstractTool):
    name: str = "kube-score"
    binary: str = "kube-score"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["kube-score", "score", "--output-format", "json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for obj in (data if isinstance(data, list) else []):
                for check in obj.get("checks", []):
                    grade = check.get("grade", "OK").upper()
                    if grade in ("OK", "SKIPPED"):
                        continue
                    sev = _GRADE_MAP.get(grade, Severity.MEDIUM)
                    name = check.get("check", {}).get("name", "")
                    comments = [c.get("summary", "") for c in check.get("comments", [])]
                    findings.append(Finding(
                        title=f"kube-score [{grade}]: {name}",
                        severity=sev,
                        description="\n".join(comments) or name,
                        tool=self.name,
                        target=target,
                        cwe=["CWE-284"],
                        raw=check,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
