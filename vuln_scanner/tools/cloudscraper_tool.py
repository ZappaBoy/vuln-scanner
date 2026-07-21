"""CloudScraper — enumerate cloud storage resources across AWS, Azure, GCP."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_FOUND_RE = re.compile(r"(?:Found|Open|Accessible)[:\s]+([^\n]+)", re.IGNORECASE)


class CloudScraperTool(AbstractTool):
    name: str = "cloudscraper"
    binary: str = "cloudscraper"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["cloudscraper", "--keyword", target, "--output", "json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for item in (data if isinstance(data, list) else data.get("results", [])):
                url = item.get("url", "")
                cloud = item.get("cloud", "")
                public = item.get("public", False)
                if url:
                    findings.append(Finding(
                        title=f"Cloud storage bucket: {url}",
                        severity=Severity.HIGH if public else Severity.MEDIUM,
                        description=f"CloudScraper found {'public' if public else 'existing'} {cloud} storage: {url}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-284"],
                        raw=item,
                    ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _FOUND_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"Cloud resource: {m.group(1).strip()[:80]}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-284"],
                        raw={"line": line},
                    ))
        return findings
