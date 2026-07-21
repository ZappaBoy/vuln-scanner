"""Quark-Engine — Android malware scoring system."""
import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class QuarkEngineTool(AbstractTool):
    name: str = "quark-engine"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["quark", "-a", target, "-s", "--output", "json_report", "/dev/stdout"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            total_score = data.get("total_score", 0)
            threat_level = data.get("threat_level", "")
            crimes = data.get("crimes", [])
            if threat_level in ("High", "Critical"):
                sev = Severity.HIGH
            elif threat_level == "Medium":
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            if total_score > 0:
                findings.append(Finding(
                    title=f"Quark Engine threat: {threat_level} (score: {total_score})",
                    severity=sev,
                    description=(
                        f"Total malware score: {total_score}\nThreat level: {threat_level}\n"
                        f"Detected crimes: {len(crimes)}"
                    ),
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw={"total_score": total_score, "threat_level": threat_level},
                ))
            for crime in crimes[:10]:  # Limit to top 10
                crime_desc = crime.get("crime", "")
                crime_score = crime.get("score", 0)
                if crime_score > 60:
                    findings.append(Finding(
                        title=f"Quark crime: {crime_desc[:80]}",
                        severity=Severity.MEDIUM,
                        description=f"Crime: {crime_desc}\nScore: {crime_score}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw=crime,
                    ))
        except json.JSONDecodeError:
            pass
        return findings
