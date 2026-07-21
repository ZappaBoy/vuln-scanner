"""Wappalyzer CLI — technology fingerprinting from HTTP responses."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_OUTDATED = re.compile(
    r"(?:outdated|vulnerable|eol|end-of-life|deprecated)", re.IGNORECASE,
)


class WappalyzerTool(AbstractTool):
    name: str = "wappalyzer"
    category: str = "system"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["wappalyzer", url, "--format", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            technologies = data.get("technologies", data) if isinstance(data, dict) else data
            if isinstance(technologies, dict):
                technologies = list(technologies.values())
            for tech in (technologies if isinstance(technologies, list) else []):
                name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
                version = tech.get("version", "") if isinstance(tech, dict) else ""
                categories = tech.get("categories", []) if isinstance(tech, dict) else []
                cat_names = [c.get("name", "") if isinstance(c, dict) else str(c) for c in categories]
                findings.append(Finding(
                    title=f"Technology: {name}" + (f" {version}" if version else ""),
                    severity=Severity.INFO,
                    description=f"Detected: {name} {version}\nCategories: {', '.join(cat_names)}",
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=tech if isinstance(tech, dict) else {"name": name},
                ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                if line.strip() and not line.startswith("#"):
                    findings.append(Finding(
                        title=f"Technology: {line.strip()[:60]}",
                        severity=Severity.INFO,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=[],
                        raw={"line": line},
                    ))
        return findings
