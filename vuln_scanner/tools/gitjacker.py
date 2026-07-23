"""gitjacker — leak git repositories from misconfigured websites."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SUCCESS_RE = re.compile(r"(?:Successfully extracted|Downloaded|Found \.git)", re.IGNORECASE)
_FILE_RE = re.compile(r"(?:downloaded|extracted)[:\s]+(.+\.(?:go|py|js|rb|php|env|conf|cfg|yml|yaml))", re.IGNORECASE)


class GitjackerTool(AbstractTool):
    name: str = "gitjacker"
    binary: str = "gitjacker"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["gitjacker", "--url", url, "--output", "/tmp/gitjacker_output"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if _SUCCESS_RE.search(raw):
            findings.append(
                Finding(
                    title=f"Exposed .git repository: {target}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"gitjacker successfully extracted a .git repository from {target}. "
                        "Source code and history may be exposed."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-548"],
                    raw={"output": raw[:500]},
                )
            )
        for m in _FILE_RE.finditer(raw):
            fname = m.group(1).strip()
            sev = Severity.HIGH if any(k in fname.lower() for k in (".env", "config", "secret")) else Severity.MEDIUM
            findings.append(
                Finding(
                    title=f"Source file exposed: {fname}",
                    severity=sev,
                    description=f"Sensitive file exposed via git repository: {fname}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-548"],
                    raw={"file": fname},
                )
            )
        return findings
