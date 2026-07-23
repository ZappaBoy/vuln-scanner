"""OpenSCAP — SCAP compliance scanner and hardening tool."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_FAIL_RE = re.compile(r"Rule result:\s+fail\s+Title:\s+(.+?)\s+Rule ID:\s+(\S+)", re.DOTALL)
_SIMPLE_FAIL = re.compile(r"FAIL\s+xccdf_[^\s]+_rule_(\S+)")


class OpenSCAPTool(AbstractTool):
    name: str = "openscap"
    binary: str = "oscap"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target can be an XCCDF or OVAL file, or "local" for host scan
        profile = "xccdf_org.ssgproject.content_profile_standard"
        if target.endswith(".xml") or target.endswith(".xccdf"):
            return [
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                profile,
                "--results",
                "/dev/stdout",
                target,
            ]
        # Host scan using a standard policy
        return [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            profile,
            "--results",
            "/dev/stdout",
            "/usr/share/xml/scap/ssg/content/ssg-almalinux9-xccdf.xml",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"FAIL\s+(xccdf_\S+_rule_\S+)", raw):
            rule_id = m.group(1)
            findings.append(
                Finding(
                    title=f"SCAP compliance failure: {rule_id}",
                    severity=Severity.MEDIUM,
                    description=f"OpenSCAP compliance check failed for rule: {rule_id}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-1173"],
                    raw={"rule_id": rule_id},
                )
            )
        return findings
