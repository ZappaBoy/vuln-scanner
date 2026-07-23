import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class DetectSecretsTool(AbstractTool):
    name: str = "detect-secrets"
    binary: str = "detect-secrets"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["detect-secrets", "scan", "--all-files", target]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for filepath, secrets in data.get("results", {}).items():
            for secret in secrets:
                secret_type = secret.get("type", "Unknown secret")
                line_number = secret.get("line_number", "")
                is_verified = secret.get("is_verified", False)
                sev = Severity.CRITICAL if is_verified else Severity.HIGH

                findings.append(
                    Finding(
                        title=f"Secret detected: {secret_type} in {filepath}",
                        severity=sev,
                        description=(
                            f"Potential {secret_type} found.\n"
                            f"File: {filepath}"
                            + (f"\nLine: {line_number}" if line_number else "")
                            + f"\nVerified: {is_verified}"
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-798"],
                        raw=secret,
                    )
                )
        return findings
