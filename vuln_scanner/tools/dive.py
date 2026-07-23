"""Dive — Docker image layer analyser (finds wasted space and secrets in layers)."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_WASTE_RE = re.compile(r"wasted space[:\s]+([\d.]+\s*\w+)", re.IGNORECASE)
_EFFICIENCY_RE = re.compile(r"image efficiency score[:\s]+([\d.]+)%", re.IGNORECASE)
_SECRET_RE = re.compile(r"(?:secret|password|credential|key|token)[^\n]*", re.IGNORECASE)


class DiveTool(AbstractTool):
    name: str = "dive"
    binary: str = "dive"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.IMAGE, TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["dive", "--ci", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        waste_m = _WASTE_RE.search(raw)
        if waste_m:
            waste = waste_m.group(1).strip()
            findings.append(
                Finding(
                    title=f"Docker image wasted space: {waste}",
                    severity=Severity.LOW,
                    description=f"dive found {waste} of wasted space in image {target}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"wasted": waste},
                )
            )
        eff_m = _EFFICIENCY_RE.search(raw)
        if eff_m:
            score = float(eff_m.group(1))
            if score < 85:
                findings.append(
                    Finding(
                        title=f"Low image efficiency score: {score:.0f}%",
                        severity=Severity.LOW,
                        description=f"dive reports image efficiency of {score:.0f}% for {target}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"efficiency": score},
                    )
                )
        if re.search(r"FAIL", raw):
            findings.append(
                Finding(
                    title=f"Image CI check failed: {target}",
                    severity=Severity.MEDIUM,
                    description="dive CI check failed — image does not meet efficiency thresholds",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={},
                )
            )
        return findings
