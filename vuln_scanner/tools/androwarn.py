"""Androwarn — static code analyzer for Android (detects malicious behavior)."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW}


class AndrowarnTool(AbstractTool):
    name: str = "androwarn"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["androwarn", "-i", target, "--report-type", "json", "--verbose", "3"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            analysis = data.get("analysis_results", {})
            for category, items in analysis.items():
                if not items:
                    continue
                sev = Severity.MEDIUM
                if any(k in category.lower() for k in ("telephony", "sms", "location", "camera")):
                    sev = Severity.HIGH
                for item in (items if isinstance(items, list) else [items]):
                    findings.append(Finding(
                        title=f"Androwarn [{category}]: {str(item)[:80]}",
                        severity=sev,
                        description=f"Detected suspicious {category}: {item}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-359"],
                        raw={"category": category, "value": item},
                    ))
        except json.JSONDecodeError:
            pass
        return findings
