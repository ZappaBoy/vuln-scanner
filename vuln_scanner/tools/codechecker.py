"""CodeChecker — C/C++ wrapping Clang Static Analyzer and Clang-Tidy."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNSPECIFIED": Severity.INFO}


class CodeCheckerTool(AbstractTool):
    name: str = "codechecker"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "CodeChecker", "analyze",
            "--build", "make",
            "--output", OUTPUT_FILE_SENTINEL,
            "--clean",
            "--compile-uniqueing", "strict",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for result in (data if isinstance(data, list) else []):
                severity_str = result.get("severity", "UNSPECIFIED").upper()
                sev = _SEV_MAP.get(severity_str, Severity.MEDIUM)
                checker = result.get("checkerId", "")
                msg = result.get("checkerMsg", "")
                fname = result.get("file", {}).get("filePath", "")
                line_num = result.get("line", "")
                findings.append(Finding(
                    title=f"CodeChecker [{checker}]: {msg[:80]}",
                    severity=sev,
                    description=f"{msg}\nFile: {fname}:{line_num}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=result,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
