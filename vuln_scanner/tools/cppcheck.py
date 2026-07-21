"""Cppcheck — C/C++ static analysis."""
import xml.etree.ElementTree as ET
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "portability": Severity.LOW, "performance": Severity.LOW,
            "style": Severity.INFO, "information": Severity.INFO}

_SECURITY_IDS = {"bufferAccessOutOfBounds", "bufferOverrun", "formatString",
                 "integerOverflow", "nullPointer", "useAfterFree", "dangerousFunction"}


class CppcheckTool(AbstractTool):
    name: str = "cppcheck"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "cppcheck",
            "--enable=all",
            "--xml",
            "--xml-version=2",
            "--output-file=" + OUTPUT_FILE_SENTINEL,
            target,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if not raw.strip():
            return findings
        try:
            root = ET.fromstring(raw)
            for err in root.findall(".//error"):
                err_id = err.get("id", "")
                severity_str = err.get("severity", "information")
                sev = _SEV_MAP.get(severity_str, Severity.INFO)
                if sev == Severity.INFO and err_id not in _SECURITY_IDS:
                    continue
                msg = err.get("msg", "")
                loc = err.find("location")
                file_loc = ""
                if loc is not None:
                    file_loc = f"{loc.get('file', '')}:{loc.get('line', '')}"
                findings.append(Finding(
                    title=f"Cppcheck [{err_id}]: {msg[:80]}",
                    severity=sev,
                    description=f"{msg}\n{file_loc}" if file_loc else msg,
                    tool=self.name,
                    target=target,
                    cwe=["CWE-119"] if err_id in _SECURITY_IDS else [],
                    raw={"id": err_id, "severity": severity_str, "msg": msg},
                ))
        except ET.ParseError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".xml")
