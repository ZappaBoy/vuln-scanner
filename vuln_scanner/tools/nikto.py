import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL, _as_url

_MODE_TUNING: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["-Tuning", "b"],           # software identification only
    ScanMode.PASSIVE:  ["-Tuning", "b"],
    ScanMode.ACTIVE:   [],                          # default tuning
    ScanMode.AGGRESSIVE: ["-Tuning", "1234567890ab"],  # all checks
}


class NiktoTool(AbstractTool):
    name: str = "nikto"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST, TargetType.IP})
    verbose_flags: list[str] = ["-Display", "V"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "nikto",
            "-h", _as_url(target),
            "-Format", "json",
            "-o", OUTPUT_FILE_SENTINEL,
            "-timeout", str(max(5, scan_input.timeout // 20)),
            "-nointeractive",
        ]
        cmd += _MODE_TUNING.get(scan_input.mode, [])
        auth = scan_input.auth
        if auth.is_configured:
            if auth.cookie_string:
                cmd += ["-cookies", auth.cookie_string]
            if auth.username and auth.password:
                cmd += ["-id", f"{auth.username}:{auth.password}"]
            for k, v in auth.headers.items():
                cmd += ["-useragent", v] if k.lower() == "user-agent" else []
        if scan_input.proxy:
            cmd += ["-useproxy", scan_input.proxy]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        if isinstance(data, list):
            hosts = data
        elif isinstance(data, dict):
            hosts = [data]
        else:
            return []

        findings: list[Finding] = []
        for host in hosts:
            for vuln in host.get("vulnerabilities", []):
                msg = vuln.get("msg", "Unknown finding")
                url = vuln.get("url", target)
                findings.append(Finding(
                    title=msg[:120],
                    severity=Severity.MEDIUM,
                    description=f"{msg}\nMethod: {vuln.get('method','?')} {url}",
                    tool=self.name,
                    target=host.get("host", target),
                    raw=vuln,
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
