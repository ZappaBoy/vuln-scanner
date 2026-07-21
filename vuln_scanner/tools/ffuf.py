import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_WORDLISTS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "/usr/share/wordlists/dirb/small.txt",
    ScanMode.PASSIVE:    "/usr/share/wordlists/dirb/common.txt",
    ScanMode.ACTIVE:     "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ScanMode.AGGRESSIVE: "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
}

_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


class FfufTool(AbstractTool):
    name: str = "ffuf"
    binary: str = "ffuf"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target.rstrip("/")
        wordlist = _WORDLISTS[scan_input.mode]
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-of", "json",
            "-o", OUTPUT_FILE_SENTINEL,
            "-mc", "all",
            "-fc", "404",
            "-noninteractive",
            "-s",
        ]
        if scan_input.rate_limit is not None:
            cmd += ["-rate", str(scan_input.rate_limit)]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
        if scan_input.proxy:
            cmd += ["--replay-proxy", scan_input.proxy]
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
        for result in data.get("results", []):
            status = result.get("status", 0)
            url = result.get("url", "")
            length = result.get("length", 0)
            words = result.get("words", 0)

            if status not in _INTERESTING_CODES:
                continue

            sev = Severity.INFO
            if status in (200, 201):
                sev = Severity.LOW
            elif status in (401, 403):
                sev = Severity.LOW
            elif status == 500:
                sev = Severity.MEDIUM

            findings.append(Finding(
                title=f"[{status}] {url}",
                severity=sev,
                description=f"Directory/file discovered: {url} (HTTP {status}, {length} bytes, {words} words)",
                tool=self.name,
                target=target,
                raw=result,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
