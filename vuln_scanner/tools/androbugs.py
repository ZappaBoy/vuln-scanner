"""AndroBugs — Android app vulnerability scanner."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_CRITICAL_RE = re.compile(r"\[Critical\]\s+(.+?)(?:\n\s{4}(.+))?", re.IGNORECASE)
_WARNING_RE = re.compile(r"\[Warning\]\s+(.+?)(?:\n\s{4}(.+))?", re.IGNORECASE)
_NOTICE_RE = re.compile(r"\[Notice\]\s+(.+)", re.IGNORECASE)


class AndroBugsTool(AbstractTool):
    name: str = "androbugs"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["androbugs", "-f", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _CRITICAL_RE.finditer(raw):
            title = m.group(1).strip()
            detail = m.group(2).strip() if m.group(2) else ""
            findings.append(Finding(
                title=f"AndroBugs [Critical]: {title[:80]}",
                severity=Severity.HIGH,
                description=f"{title}\n{detail}" if detail else title,
                tool=self.name,
                target=target,
                cwe=[],
                raw={"title": title},
            ))
        for m in _WARNING_RE.finditer(raw):
            title = m.group(1).strip()
            detail = m.group(2).strip() if m.group(2) else ""
            findings.append(Finding(
                title=f"AndroBugs [Warning]: {title[:80]}",
                severity=Severity.MEDIUM,
                description=f"{title}\n{detail}" if detail else title,
                tool=self.name,
                target=target,
                cwe=[],
                raw={"title": title},
            ))
        return findings
