"""weggli — fast C/C++ semantic search for vulnerability patterns."""
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

# Vulnerability patterns: (pattern, title, cwe, severity)
_PATTERNS = [
    (r'{_ $buf[_]; memcpy($buf, _, _);}', "Stack buffer overwrite via memcpy", "CWE-121", Severity.HIGH),
    (r'{strcpy($dst, $src);}', "Unsafe strcpy usage", "CWE-120", Severity.HIGH),
    (r'{sprintf($buf, $fmt, _);}', "Unsafe sprintf usage", "CWE-134", Severity.MEDIUM),
    (r'{system($cmd);}', "Command injection via system()", "CWE-78", Severity.CRITICAL),
    (r'{exec($_, $cmd, _);}', "Command injection via exec", "CWE-78", Severity.CRITICAL),
    (r'{gets($buf);}', "Use of dangerous gets()", "CWE-120", Severity.CRITICAL),
]


class WeggliTool(AbstractTool):
    name: str = "weggli"
    binary: str = "weggli"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if re.search(r"\[MATCH\]|\.c:|\.cpp:|\.h:", line):
                findings.append(Finding(
                    title=f"weggli pattern match: {line[:80]}",
                    severity=Severity.MEDIUM,
                    description=line.strip(),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-119"],
                    raw={"line": line},
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        all_findings: list = []
        start = time.monotonic()
        last_error = ""
        for pattern, title, cwe, sev in _PATTERNS:
            try:
                proc = subprocess.run(
                    ["weggli", pattern, target],
                    capture_output=True, text=True,
                    timeout=min(30, scan_input.timeout // len(_PATTERNS)),
                )
                if proc.stdout.strip():
                    for line in proc.stdout.strip().splitlines():
                        if line.strip():
                            all_findings.append(Finding(
                                title=title,
                                severity=sev,
                                description=f"{title}\n{line.strip()}",
                                tool=self.name,
                                target=target,
                                cwe=[cwe],
                                raw={"pattern": pattern, "match": line},
                            ))
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                last_error = str(e)
        duration = time.monotonic() - start
        if last_error and "not found" in last_error.lower():
            return ScanResult(tool=self.name, target=target, duration=duration,
                              status=ScanStatus.FAILED, error="Binary not found: weggli")
        return ScanResult(
            tool=self.name, target=target,
            findings=all_findings, duration=duration,
            status=ScanStatus.SUCCESS, raw_output="",
        )
