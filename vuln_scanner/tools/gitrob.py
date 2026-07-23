"""Gitrob — GitHub organisation recon and secret hunting."""

import json
import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SENSITIVE = re.compile(
    r"(?:password|secret|key|token|credential|private|api_key|access_token)",
    re.IGNORECASE,
)


class GitrobTool(AbstractTool):
    name: str = "gitrob"
    binary: str = "gitrob"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        org = target.replace("https://github.com/", "").split("/")[0]
        cmd = ["gitrob", "--output-json", "/dev/stdout", org]
        if scan_input.auth.bearer_token:
            cmd = ["gitrob", "--github-access-token", scan_input.auth.bearer_token, "--output-json", "/dev/stdout", org]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for finding in data.get("findings", []):
                path = finding.get("path", "")
                desc = finding.get("description", "")
                url = finding.get("url", "")
                sev = Severity.HIGH if _SENSITIVE.search(desc + path) else Severity.MEDIUM
                findings.append(
                    Finding(
                        title=f"Gitrob: {desc[:80]}",
                        severity=sev,
                        description=f"{desc}\nFile: {path}\nURL: {url}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-200"],
                        raw=finding,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
