"""Insider — SAST for mobile and web (Swift, Kotlin, Java, JS, C#)."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}


class InsiderTool(AbstractTool):
    name: str = "insider"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "insider",
            "--tech", "auto",
            "--target", target,
            "--output", OUTPUT_FILE_SENTINEL,
            "--format", "json",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", []):
                sev_str = vuln.get("severity", "medium").lower()
                sev = _SEV_MAP.get(sev_str, Severity.MEDIUM)
                class_name = vuln.get("classMessage", "")
                method = vuln.get("methodMessage", "")
                desc = vuln.get("longMessage", vuln.get("shortMessage", ""))
                fname = vuln.get("classFile", "")
                line_num = vuln.get("line", "")
                findings.append(Finding(
                    title=f"Insider: {class_name or method or desc[:60]}",
                    severity=sev,
                    description=f"{desc}\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=[vuln.get("cwe", "")] if vuln.get("cwe") else [],
                    raw=vuln,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
