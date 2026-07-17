import json

from vuln_scanner.tools.enums import TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class HadolintTool(AbstractTool):
    name: str = "hadolint"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        import os
        # Find Dockerfiles under target
        dockerfiles = []
        if os.path.isfile(target) and "dockerfile" in os.path.basename(target).lower():
            dockerfiles = [target]
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for f in files:
                    if "dockerfile" in f.lower():
                        dockerfiles.append(os.path.join(root, f))

        cmd = ["hadolint", "-f", "json"] + (dockerfiles or [target])
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
        for item in data if isinstance(data, list) else []:
            sev = _parse_severity(item.get("level", "warning"))
            rule = item.get("code", "")
            message = item.get("message", "")
            filename = item.get("file", target)
            line = item.get("line", "")

            findings.append(Finding(
                title=f"{rule}: {message[:80]}",
                severity=sev,
                description=(
                    f"{message}\n"
                    f"File: {filename}" + (f"\nLine: {line}" if line else "")
                ),
                tool=self.name,
                target=target,
                references=[f"https://github.com/hadolint/hadolint/wiki/{rule}" if rule else ""],
                raw=item,
            ))
        return findings
