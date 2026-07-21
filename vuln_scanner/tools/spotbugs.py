"""SpotBugs — Java bytecode static analysis."""
import xml.etree.ElementTree as ET
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_PRIORITY_MAP = {"1": Severity.HIGH, "2": Severity.MEDIUM, "3": Severity.LOW}


class SpotBugsTool(AbstractTool):
    name: str = "spotbugs"
    binary: str = "spotbugs"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "spotbugs", "-textui", "-xml:withMessages",
            "-output", OUTPUT_FILE_SENTINEL,
            target,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if not raw.strip():
            return findings
        try:
            root = ET.fromstring(raw)
            for bug in root.findall(".//BugInstance"):
                bug_type = bug.get("type", "")
                priority = bug.get("priority", "3")
                sev = _PRIORITY_MAP.get(priority, Severity.LOW)
                msg_elem = bug.find("LongMessage")
                msg = msg_elem.text if msg_elem is not None else bug_type
                source = bug.find(".//SourceLine")
                loc = ""
                if source is not None:
                    loc = f"{source.get('sourcepath', '')}:{source.get('start', '')}"
                findings.append(Finding(
                    title=f"SpotBugs [{bug_type}]: {msg[:80]}",
                    severity=sev,
                    description=f"{msg}\nLocation: {loc}" if loc else msg,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"type": bug_type, "priority": priority, "location": loc},
                ))
        except ET.ParseError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".xml")
