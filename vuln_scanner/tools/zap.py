import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL, _as_url

_RISK_SEVERITY: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class ZAPTool(AbstractTool):
    name: str = "zap"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "zaproxy", "-cmd",
            "-quickurl", _as_url(target),
            "-quickout", OUTPUT_FILE_SENTINEL,
            "-quickprogress",
        ]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            # Passive scan only — no active attack
            cmd += ["-config", "scanner.attackOnStart=false"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-config", "scanner.attackOnStart=true",
                    "-config", "scanner.threadPerHost=5"]

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
        for site in data.get("site", []):
            site_name = site.get("@name", target)
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskcode", "0"))
                severity = _RISK_SEVERITY.get(risk, Severity.INFO)
                refs = [r.strip() for r in alert.get("reference", "").splitlines() if r.strip()]
                instances = alert.get("instances", [{}])
                uri = instances[0].get("uri", site_name) if instances else site_name
                findings.append(Finding(
                    title=alert.get("name", alert.get("alert", "ZAP finding")),
                    severity=severity,
                    description=(
                        alert.get("desc", "").replace("<p>", "").replace("</p>", "\n").strip()
                        + "\nSolution: "
                        + alert.get("solution", "").replace("<p>", "").replace("</p>", "").strip()
                    ),
                    tool=self.name,
                    target=uri or site_name,
                    references=refs,
                    raw=alert,
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
