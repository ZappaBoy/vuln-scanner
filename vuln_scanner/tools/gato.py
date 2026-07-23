"""Gato — GitHub Actions self-hosted runner enumeration and exploitation."""

import json
import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_RUNNER_RE = re.compile(r"(?:runner|self-hosted)[:\s]+(.+)", re.IGNORECASE)
_SECRET_RE = re.compile(r"(?:secret|token|credential)[:\s]+(.+)", re.IGNORECASE)


class GatoTool(AbstractTool):
    name: str = "gato"
    binary: str = "gato-x"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        org = target.replace("https://github.com/", "").split("/")[0]
        cmd = [self.binary, "enumerate", "--org", org, "--output-json"]
        if scan_input.auth.bearer_token:
            cmd += ["--token", scan_input.auth.bearer_token]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            runners = data.get("self_hosted_runners", [])
            for runner in runners:
                name = runner.get("name", "unknown")
                os_info = runner.get("os", "")
                findings.append(
                    Finding(
                        title=f"Self-hosted runner: {name}",
                        severity=Severity.HIGH,
                        description=(
                            f"gato found self-hosted runner '{name}' ({os_info}) in GitHub org {target}. "
                            "Self-hosted runners may be vulnerable to poisoned workflow attacks."
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-693"],
                        raw=runner,
                    )
                )
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _RUNNER_RE.search(line)
                if m:
                    findings.append(
                        Finding(
                            title=f"GitHub Actions runner: {m.group(1).strip()[:80]}",
                            severity=Severity.HIGH,
                            description=line.strip(),
                            tool=self.name,
                            target=target,
                            cwe=["CWE-693"],
                            raw={"line": line},
                        )
                    )
        return findings
