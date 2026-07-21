import json
import os

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


class CherrybombTool(AbstractTool):
    name: str = "cherrybomb"
    binary: str = "cherrybomb"
    category: str = "api"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target: path to an OpenAPI/Swagger spec file, or a URL pointing to one
        if os.path.isfile(target):
            spec = target
        else:
            spec = target   # cherrybomb can also accept a URL to the spec
        cmd = ["cherrybomb", "--file", spec, "--format", "json"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["--verbosity", "2"]

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
        checks = data if isinstance(data, list) else data.get("checks", data.get("results", []))

        for item in checks:
            status = item.get("status", item.get("result", ""))
            if str(status).lower() in ("pass", "ok", "passed", True, "true"):
                continue

            name = item.get("name", item.get("check", ""))
            description = item.get("description", item.get("message", ""))
            severity_raw = item.get("severity", item.get("level", "medium"))
            sev = _SEV_MAP.get(str(severity_raw).lower(), Severity.MEDIUM)
            endpoint = item.get("endpoint", item.get("path", ""))
            method = item.get("method", "")

            title = name
            if method and endpoint:
                title += f" — {method} {endpoint}"

            findings.append(Finding(
                title=title,
                severity=sev,
                description=description or title,
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings
