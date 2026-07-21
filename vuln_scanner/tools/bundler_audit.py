"""Bundler-audit — Ruby gems vulnerability scanner."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_NAME_RE = re.compile(r"Name:\s+(\S+)")
_VERSION_RE = re.compile(r"Version:\s+(\S+)")
_CVE_RE = re.compile(r"CVE:\s+(CVE-\S+)")
_ADVISORY_RE = re.compile(r"Advisory:\s+(\S+)")
_TITLE_RE = re.compile(r"Title:\s+(.+)")
_CRITICALITY_RE = re.compile(r"Criticality:\s+(\S+)", re.IGNORECASE)

_SEV_MAP = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


class BundlerAuditTool(AbstractTool):
    name: str = "bundler-audit"
    binary: str = "bundle-audit"
    category: str = "sca"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["bundle-audit", "check", "--update", "--gemfile", f"{target}/Gemfile"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        # Parse grouped vulnerability blocks
        blocks = re.split(r"\n(?=Name:)", raw)
        for block in blocks:
            name_m = _NAME_RE.search(block)
            version_m = _VERSION_RE.search(block)
            cve_m = _CVE_RE.search(block)
            title_m = _TITLE_RE.search(block)
            crit_m = _CRITICALITY_RE.search(block)
            if not name_m:
                continue
            name = name_m.group(1)
            version = version_m.group(1) if version_m else ""
            cve = cve_m.group(1) if cve_m else ""
            title = title_m.group(1).strip() if title_m else ""
            crit = (crit_m.group(1) if crit_m else "medium").lower()
            sev = _SEV_MAP.get(crit, Severity.MEDIUM)
            findings.append(Finding(
                title=f"bundler-audit [{name} {version}]: {title or cve}",
                severity=sev,
                description=f"Vulnerable gem: {name} {version}\n{title}",
                tool=self.name,
                target=target,
                cwe=["CWE-1035"],
                cve=[cve] if cve else [],
                raw={"name": name, "version": version, "cve": cve},
            ))
        return findings
