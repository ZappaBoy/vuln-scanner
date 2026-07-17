import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_CHUNK: dict[ScanMode, int] = {
    ScanMode.PARANOID:    50,
    ScanMode.PASSIVE:    250,
    ScanMode.ACTIVE:     500,
    ScanMode.AGGRESSIVE: 1000,
}


class ArjunTool(AbstractTool):
    name: str = "arjun"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "arjun",
            "-u", target,
            "-o", OUTPUT_FILE_SENTINEL,
            "-c", str(_CHUNK[scan_input.mode]),
            "-q",
        ]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-m", "GET,POST,JSON,XML", "--stable"]
        if scan_input.rate_limit is not None:
            cmd += ["-d", str(max(0, 1000 // scan_input.rate_limit))]
        auth = scan_input.auth
        if auth.is_configured:
            import json as _json
            headers = dict(auth.effective_headers)
            cmd += ["--headers", _json.dumps(headers)]
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

        # arjun JSON: {url: {GET: [params], POST: [params], ...}}
        if isinstance(data, dict):
            for url, methods in data.items():
                if not isinstance(methods, dict):
                    continue
                for method, params in methods.items():
                    if not params:
                        continue
                    findings.append(Finding(
                        title=f"Parameters found: {method} {url}",
                        severity=Severity.INFO,
                        description=(
                            f"Hidden parameters discovered on {url} ({method}): "
                            + ", ".join(str(p) for p in params)
                        ),
                        tool=self.name,
                        target=target,
                        raw={"url": url, "method": method, "params": params},
                    ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
