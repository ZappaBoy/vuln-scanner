"""ESLint — JavaScript/TypeScript linter with security plugins."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP = {2: Severity.HIGH, 1: Severity.MEDIUM, 0: Severity.INFO}
_SEC_RULES = {
    "no-eval",
    "no-implied-eval",
    "no-new-func",
    "no-script-url",
    "security/detect-eval-with-expression",
    "security/detect-non-literal-regexp",
    "security/detect-non-literal-fs-filename",
    "security/detect-possible-timing-attacks",
}


class ESLintTool(AbstractTool):
    name: str = "eslint"
    binary: str = "eslint"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [
            "eslint",
            "--format",
            "json",
            "--no-eslintrc",
            "--plugin",
            "security",
            "--rule",
            '{"security/detect-eval-with-expression": "error", "no-eval": "error"}',
            "--ext",
            ".js,.ts,.mjs",
            target,
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for file_result in data:
                fname = file_result.get("filePath", "")
                for msg in file_result.get("messages", []):
                    rule = msg.get("ruleId", "")
                    severity_num = msg.get("severity", 1)
                    sev = _SEV_MAP.get(severity_num, Severity.MEDIUM)
                    if rule not in _SEC_RULES:
                        sev = Severity.INFO
                    message = msg.get("message", "")
                    line_num = msg.get("line", "")
                    findings.append(
                        Finding(
                            title=f"ESLint [{rule}]: {message[:60]}",
                            severity=sev,
                            description=f"{message}\nFile: {fname}:{line_num}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw=msg,
                        )
                    )
        except json.JSONDecodeError:
            pass
        return findings
