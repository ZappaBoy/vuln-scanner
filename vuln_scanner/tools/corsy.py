"""Corsy — CORS misconfiguration scanner."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_RE = re.compile(r"VULNERABLE|Misconfiguration", re.IGNORECASE)


class CorsyTool(AbstractTool):
    name: str = "corsy"
    binary: str = "python3"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["python3", "/opt/Corsy/corsy.py", "-u", url, "-t", "10", "--headers",
                "User-Agent: Mozilla/5.0"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        # JSON output mode
        try:
            data = json.loads(raw)
            for url, result in (data if isinstance(data, dict) else {}).items():
                if isinstance(result, dict) and result.get("class"):
                    cls = result["class"]
                    sev = Severity.HIGH if "Reflect" in cls or "Null" in cls else Severity.MEDIUM
                    findings.append(Finding(
                        title=f"CORS Misconfiguration ({cls}): {url}",
                        severity=sev,
                        description=(
                            f"Corsy found a {cls} CORS misconfiguration on {url}.\n"
                            f"Origin tested: {result.get('origin', 'unknown')}"
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-942"],
                        raw=result,
                    ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                if _VULN_RE.search(line):
                    findings.append(Finding(
                        title=f"CORS Misconfiguration on {target}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-942"],
                        raw={"line": line},
                    ))
        return findings
