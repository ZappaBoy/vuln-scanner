"""Quark-Engine — Android malware scoring system."""

import json

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class QuarkEngineTool(AbstractTool):
    name: str = "quark-engine"
    binary: str = "quark"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})
    consumes: frozenset[AssetType] = frozenset({AssetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # quark -a expects an APK file; if target is a directory, look for *.apk inside
        import os
        if os.path.isdir(target):
            apks = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(".apk")]
            apk_path = apks[0] if apks else os.path.join(target, "app.apk")
        else:
            apk_path = target
        # -s summary; rules downloaded at image build time via `quark --update`.
        return ["quark", "-a", apk_path, "-s"]

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
                findings.append(
                    Finding(
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
                    )
                )
            for crime in crimes[:10]:  # Limit to top 10
                crime_desc = crime.get("crime", "")
                crime_score = crime.get("score", 0)
                if crime_score > 60:
                    findings.append(
                        Finding(
                            title=f"Quark crime: {crime_desc[:80]}",
                            severity=Severity.MEDIUM,
                            description=f"Crime: {crime_desc}\nScore: {crime_score}",
                            tool=self.name,
                            target=target,
                            cwe=[],
                            raw=crime,
                        )
                    )
        except json.JSONDecodeError:
            pass
        return findings
