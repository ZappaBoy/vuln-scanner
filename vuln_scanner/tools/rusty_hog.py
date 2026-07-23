"""Rusty Hog — New Relic's suite of Rust-based secret scanners.

The suite installs one binary per source type: choctaw_hog (git repos),
duroc_hog (filesystem/archives), berkshire_hog (S3), ankamali_hog (Google Drive),
essex_hog (Confluence), gottingen_hog (Jira) and hante_hog (Slack). Only the two
credential-free scanners (choctaw/git, duroc/filesystem) are driven here; the
rest are available as binaries but require service credentials/IDs to run.
"""
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
        # Rusty Hog has no --json flag; JSON is emitted to stdout by default.
        # --prettyprint keeps it valid JSON (indented) for parse_output.
        if _GIT_TARGET.search(target):
            # choctaw_hog scans a git repo (local path or remote URL).
            return ["choctaw_hog", "--prettyprint", target]
        # duroc_hog scans a filesystem path; -z also descends into ZIP/TAR archives.
        return ["duroc_hog", "--prettyprint", "-z", target]

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
