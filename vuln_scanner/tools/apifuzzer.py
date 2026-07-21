import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL


class APIFuzzerTool(AbstractTool):
    name: str = "apifuzzer"
    binary: str = "APIFuzzer"
    category: str = "api"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target may be:
        #   - a URL  (server base URL; spec must be provided via --src_file in extra_args)
        #   - a file path (OpenAPI/Swagger spec; server is inferred from the spec)
        import os as _os
        if _os.path.isfile(target):
            cmd = ["APIFuzzer", "--src_file", target, "--report_file", OUTPUT_FILE_SENTINEL]
        else:
            cmd = ["APIFuzzer", "--url", target, "--report_file", OUTPUT_FILE_SENTINEL]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            cmd += ["--level", "1"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--level", "3"]

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
        results = data if isinstance(data, list) else data.get("results", data.get("tests", []))

        for item in results:
            endpoint = item.get("endpoint", item.get("path", ""))
            method = item.get("method", "")
            status = item.get("status_code", item.get("status", 0))
            result = item.get("result", item.get("status", ""))
            description = item.get("description", item.get("reason", ""))

            if str(result).lower() in ("pass", "ok", "success"):
                continue

            sev_raw = item.get("severity", "medium")
            sev = _parse_severity(str(sev_raw))

            if status == 500:
                sev = Severity.HIGH

            findings.append(Finding(
                title=f"API fuzz: {method} {endpoint} [{status}]",
                severity=sev,
                description=(
                    f"Unexpected response from {method} {endpoint}: "
                    f"HTTP {status}. {description}"
                ).strip(),
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
