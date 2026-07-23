import json

from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SKIP_SEVERITIES = {"ok", "info", "hint", "debug", "not tested"}

# testssl IDs that are scanner diagnostics, not target vulnerabilities
_SKIP_IDS = {"engine_problem", "scanTime", "scanProblem", "fileCreation", "service", "pre_info"}

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--protocols", "--headers", "--cipher-per-proto"],
    ScanMode.PASSIVE: ["--protocols", "--headers", "--cipher-per-proto", "--server-defaults"],
    ScanMode.ACTIVE: [],  # standard run
    ScanMode.AGGRESSIVE: ["--full"],  # all checks including client simulation
}


class TestSSLTool(AbstractTool):
    name: str = "testssl"
    binary: str = "testssl"
    category: str = "ssl"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("https://", "").replace("http://", "")
        if ":" not in host:
            host = f"{host}:443"
        cmd = [
            "testssl",
            "--jsonfile",
            OUTPUT_FILE_SENTINEL,
            "--quiet",
            "--nodns",
            "min",
        ]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        cmd.append(host)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            return []

        if not isinstance(items, list):
            items = items.get("scanResult", [{}])[0].get("findings", [])

        findings: list[Finding] = []
        for item in items:
            sev_raw = item.get("severity", "ok").lower()
            if sev_raw in _SKIP_SEVERITIES:
                continue
            if item.get("id", "") in _SKIP_IDS:
                continue
            severity = _parse_severity(sev_raw)
            cve_raw = item.get("cve", "")
            cves = [c.strip() for c in cve_raw.split() if c.startswith("CVE-")]
            findings.append(
                Finding(
                    title=f"[{item.get('id', '?')}] {item.get('finding', '')[:120]}",
                    severity=severity,
                    description=item.get("finding", ""),
                    tool=self.name,
                    target=target,
                    cve=cves,
                    raw=item,
                )
            )
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
