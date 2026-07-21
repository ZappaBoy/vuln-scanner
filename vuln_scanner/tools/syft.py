"""Syft — SBOM generation tool (pairs with Grype for vulnerability scanning)."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class SyftTool(AbstractTool):
    name: str = "syft"
    binary: str = "syft"
    category: str = "container"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.PATH, TargetType.IMAGE, TargetType.URL,
    })

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "syft", target,
            "-o", f"json={OUTPUT_FILE_SENTINEL}",
            "--quiet",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            artifacts = data.get("artifacts", [])
            # Report notable findings: packages with no declared license
            unlicensed = [a for a in artifacts if not a.get("licenses")]
            if unlicensed:
                findings.append(Finding(
                    title=f"SBOM: {len(artifacts)} packages ({len(unlicensed)} without license)",
                    severity=Severity.INFO,
                    description=(
                        f"Syft generated SBOM for {target}.\n"
                        f"Total packages: {len(artifacts)}\n"
                        f"Packages without declared license: {len(unlicensed)}"
                    ),
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"total": len(artifacts), "unlicensed": len(unlicensed)},
                ))
            elif artifacts:
                findings.append(Finding(
                    title=f"SBOM generated: {len(artifacts)} packages",
                    severity=Severity.INFO,
                    description=f"Syft generated SBOM for {target}: {len(artifacts)} packages.",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"total": len(artifacts)},
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
