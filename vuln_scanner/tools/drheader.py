import json

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class DrheaderTool(AbstractTool):
    name: str = "drheader"
    binary: str = "drheader"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["drheader", "scan", "single", _as_url(target), "--json"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            return []

        if isinstance(items, dict):
            items = items.get("report", [items])

        findings: list[Finding] = []
        for item in items:
            sev_label = (item.get("severity") or item.get("Severity") or "medium").lower()
            severity = _SEVERITY_MAP.get(sev_label, Severity.MEDIUM)
            rule = item.get("rule") or item.get("Rule") or "Header check"
            message = item.get("message") or item.get("Message") or rule
            expected = item.get("expected") or item.get("Expected") or ""
            actual = item.get("value") or item.get("Value") or item.get("actual") or "missing"
            findings.append(
                Finding(
                    title=f"HTTP Header: {rule}",
                    severity=severity,
                    description=(f"{message}\nExpected: {expected}\nActual:   {actual}"),
                    tool=self.name,
                    target=target,
                    raw=item,
                )
            )
        return findings
