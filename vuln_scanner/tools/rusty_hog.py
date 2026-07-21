"""Rusty Hog — Rust-based secret scanner for git, S3, Jira, Confluence."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_GIT_TARGET = re.compile(r"(?:\.git|github\.com|gitlab\.com|bitbucket\.org)")


class RustyHogTool(AbstractTool):
    name: str = "rusty-hog"
    binary: str = "choctaw_hog"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        if _GIT_TARGET.search(target):
            return ["choctaw_hog", "--json", target]
        return ["duroc_hog", "--json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            secrets = data if isinstance(data, list) else data.get("secrets", [])
            for secret in secrets:
                reason = secret.get("reason", "secret")
                commit = secret.get("commit", "")
                date = secret.get("date", "")
                path = secret.get("path", "")
                findings.append(Finding(
                    title=f"Rusty Hog [{reason}]: {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"Secret found: {reason}\n"
                        f"File: {path}"
                        + (f"\nCommit: {commit}" if commit else "")
                        + (f"\nDate: {date}" if date else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-798"],
                    raw={k: v for k, v in secret.items() if k != "stringsFound"},
                ))
        except json.JSONDecodeError:
            pass
        return findings
