"""APKLeaks — scan APK files for URIs, endpoints, and secrets."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_HIGH_PATTERNS = {"google_api", "firebase", "aws_key", "private_key", "secret", "password", "token"}


class APKLeaksTool(AbstractTool):
    name: str = "apkleaks"
    binary: str = "apkleaks"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["apkleaks", "--apk", target, "--json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for match_name, values in data.items():
                is_sensitive = any(p in match_name.lower() for p in _HIGH_PATTERNS)
                sev = Severity.HIGH if is_sensitive else Severity.INFO
                for val in values if isinstance(values, list) else [values]:
                    findings.append(
                        Finding(
                            title=f"APKLeaks [{match_name}]: {str(val)[:60]}",
                            severity=sev,
                            description=f"Pattern '{match_name}' matched: {val}",
                            tool=self.name,
                            target=target,
                            cwe=["CWE-798"] if is_sensitive else ["CWE-200"],
                            raw={"pattern": match_name, "value": "[REDACTED]" if is_sensitive else val},
                        )
                    )
        except json.JSONDecodeError:
            pass
        return findings
