"""Cloudfox — AWS/Azure attack surface discovery for pentesting."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_FINDING_RE = re.compile(r"\[(?:HIGH|MEDIUM|LOW|INFO)\]\s+(.+)", re.IGNORECASE)
_LEVEL_RE = re.compile(r"\[(HIGH|MEDIUM|LOW|INFO)\]", re.IGNORECASE)
_SEV_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW, "INFO": Severity.INFO}


class CloudfoxTool(AbstractTool):
    name: str = "cloudfox"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        provider = "aws" if "aws" in target.lower() else "azure"
        return ["cloudfox", provider, "all-checks", "--output", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            level_m = _LEVEL_RE.search(line)
            msg_m = _FINDING_RE.search(line)
            if level_m and msg_m:
                level = level_m.group(1).upper()
                sev = _SEV_MAP.get(level, Severity.INFO)
                if sev == Severity.INFO:
                    continue
                msg = msg_m.group(1).strip()
                findings.append(Finding(
                    title=f"Cloudfox [{level}]: {msg[:80]}",
                    severity=sev,
                    description=msg,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"line": line},
                ))
        return findings
