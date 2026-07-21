"""Dockle — container image security linting."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"FATAL": Severity.CRITICAL, "WARN": Severity.HIGH,
            "INFO": Severity.INFO, "SKIP": Severity.INFO, "PASS": Severity.INFO}


class DockleTool(AbstractTool):
    name: str = "dockle"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IMAGE, TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["dockle", "--format", "json", "--output", OUTPUT_FILE_SENTINEL, target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in data.get("details", []):
                level = item.get("level", "INFO").upper()
                if level in ("PASS", "SKIP"):
                    continue
                sev = _SEV_MAP.get(level, Severity.MEDIUM)
                code = item.get("code", "")
                alerts = item.get("alerts", [])
                desc = "\n".join(alerts) if alerts else item.get("title", "")
                findings.append(Finding(
                    title=f"Dockle [{level}] {code}: {item.get('title', '')}",
                    severity=sev,
                    description=desc,
                    tool=self.name,
                    target=target,
                    cwe=["CWE-732"],
                    raw=item,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
