"""APKiD — Android APK packer/protector identification."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_DANGEROUS = {"obfuscator", "packer", "protector", "anti_debug", "anti_emulation", "dropper"}


class APKiDTool(AbstractTool):
    name: str = "apkid"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["apkid", "--json", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for file_result in data.get("files", []):
                fname = file_result.get("filename", "")
                matches = file_result.get("matches", {})
                for category, items in matches.items():
                    is_suspicious = any(d in category.lower() for d in _DANGEROUS)
                    sev = Severity.HIGH if is_suspicious else Severity.INFO
                    for item in (items if isinstance(items, list) else [items]):
                        findings.append(Finding(
                            title=f"APKiD [{category}]: {str(item)[:60]}",
                            severity=sev,
                            description=f"Detected {category} in {fname}: {item}",
                            tool=self.name,
                            target=target,
                            cwe=["CWE-494"] if is_suspicious else [],
                            raw={"category": category, "match": item, "file": fname},
                        ))
        except json.JSONDecodeError:
            pass
        return findings
