"""JSParser — parse relative URLs from JavaScript files."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_URL_RE = re.compile(r"((?:https?://|/)[^\s\"'<>]+)", re.IGNORECASE)
_API_RE = re.compile(r"(/api/[^\s\"'<>]+)", re.IGNORECASE)
_INTERESTING = re.compile(
    r"(?:admin|secret|key|token|password|passwd|auth|config|backup|\.git|\.env)",
    re.IGNORECASE,
)


class JSParserTool(AbstractTool):
    name: str = "jsparser"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["python3", "/opt/JSParser/handler.py", url]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                seen.add(line)
                sev = Severity.MEDIUM if _INTERESTING.search(line) else Severity.INFO
                if sev == Severity.MEDIUM or _API_RE.match(line):
                    findings.append(Finding(
                        title=f"JS endpoint: {line[:80]}",
                        severity=sev,
                        description=f"JSParser found endpoint in JavaScript: {line}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-538"],
                        raw={"endpoint": line},
                    ))
        return findings
