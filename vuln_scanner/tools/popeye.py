"""Popeye — Kubernetes live cluster resource sanitizer."""

import json

from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_LEVEL_MAP = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH, 4: Severity.CRITICAL}


class PopeyeTool(AbstractTool):
    name: str = "popeye"
    binary: str = "popeye"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["popeye", "-o", "json", "--save", "--out", OUTPUT_FILE_SENTINEL]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            sanitizer = data.get("popeye", {}).get("sanitizers", {})
            for resource, info in sanitizer.items():
                for issue_list in info.get("issues", {}).values():
                    for issue in issue_list:
                        level = issue.get("level", 0)
                        if level < 2:
                            continue
                        sev = _LEVEL_MAP.get(level, Severity.MEDIUM)
                        msg = issue.get("message", "")
                        findings.append(
                            Finding(
                                title=f"Popeye [{resource}]: {msg[:60]}",
                                severity=sev,
                                description=f"Resource: {resource}\n{msg}",
                                tool=self.name,
                                target=target,
                                cwe=["CWE-284"],
                                raw=issue,
                            )
                        )
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
