"""SARIF importer — import vulnerability reports in SARIF universal format."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "note": Severity.LOW, "none": Severity.INFO}


class SARIFImporterTool(AbstractTool):
    name: str = "sarif-import"
    category: str = "generic"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Target is a SARIF file; just cat it
        return ["cat", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            sarif = json.loads(raw)
            for run in sarif.get("runs", []):
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
                rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
                for result in run.get("results", []):
                    level = result.get("level", "warning")
                    sev = _SEV_MAP.get(level, Severity.MEDIUM)
                    rule_id = result.get("ruleId", "")
                    msg = result.get("message", {}).get("text", "")
                    locations = result.get("locations", [])
                    loc = ""
                    if locations:
                        pl = locations[0].get("physicalLocation", {})
                        uri = pl.get("artifactLocation", {}).get("uri", "")
                        line_num = pl.get("region", {}).get("startLine", "")
                        loc = f"{uri}:{line_num}" if line_num else uri
                    # Look up CWE from rule metadata
                    rule_meta = rules.get(rule_id, {})
                    cwe_tags = [
                        t for t in rule_meta.get("properties", {}).get("tags", [])
                        if t.startswith("CWE-")
                    ]
                    findings.append(Finding(
                        title=f"[{tool_name}] {rule_id}: {msg[:80]}",
                        severity=sev,
                        description=f"Tool: {tool_name}\n{msg}\nLocation: {loc}",
                        tool=self.name,
                        target=target,
                        cwe=cwe_tags,
                        raw=result,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
