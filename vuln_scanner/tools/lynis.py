"""Lynis — system security audit for Linux/macOS/Unix hosts."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# "[WARNING] ..." or "* Warning [AUTH-9328] : ..."
_WARN_RE = re.compile(
    r"(?:Warning|WARNING)\s*\[(?P<id>[A-Z0-9_\-]+)\]\s*[:\-]?\s*(?P<msg>.+)"
)
_SUGG_RE = re.compile(
    r"(?:Suggestion|SUGGESTION)\s*\[(?P<id>[A-Z0-9_\-]+)\]\s*[:\-]?\s*(?P<msg>.+)"
)
_CRIT_RE = re.compile(
    r"(?:Critical|CRITICAL)\s*\[(?P<id>[A-Z0-9_\-]+)\]\s*[:\-]?\s*(?P<msg>.+)"
)

_SEV_MAP = {
    "CRITICAL": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "SUGGESTION": Severity.LOW,
}


class LynisTool(AbstractTool):
    name: str = "lynis"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.HOST, TargetType.IP, TargetType.PATH,
    })

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "lynis", "audit", "system",
            "--no-colors", "--quiet", "--quick",
            "--noplugins",
        ]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            line = line.strip()
            for pattern, sev_key in (
                (_CRIT_RE, "CRITICAL"),
                (_WARN_RE, "WARNING"),
                (_SUGG_RE, "SUGGESTION"),
            ):
                m = pattern.search(line)
                if m:
                    test_id = m.group("id")
                    msg = m.group("msg").strip()
                    key = f"{test_id}:{msg[:60]}"
                    if key in seen:
                        break
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Lynis [{test_id}]: {msg[:80]}",
                        severity=_SEV_MAP[sev_key],
                        description=f"Lynis system audit {sev_key.lower()}: {msg}\nTest ID: {test_id}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-732"] if sev_key == "WARNING" else [],
                        raw={"test_id": test_id, "level": sev_key, "message": msg},
                    ))
                    break

        return findings
