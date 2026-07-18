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

_DEPTH: dict[ScanMode, int] = {
    ScanMode.PARANOID: 1, ScanMode.PASSIVE: 2,
    ScanMode.ACTIVE: 4,   ScanMode.AGGRESSIVE: 8,
}


class FeroxbusterTool(AbstractTool):
    name: str = "feroxbuster"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        wordlist = _WORDLISTS[scan_input.mode]
        depth = _DEPTH[scan_input.mode]
        cmd = [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist,
            "--depth", str(depth),
            "--json",
            "--output", OUTPUT_FILE_SENTINEL,
            "--silent",
            "--no-state",
        ]
        if scan_input.rate_limit is not None:
            cmd += ["--rate-limit", str(scan_input.rate_limit)]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
            if auth.cookie_string:
                cmd += ["--cookies", auth.cookie_string]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            if item.get("type") != "response":
                continue

            status = item.get("status", 0)
            url = item.get("url", "")
            if not url or status == 404:
                continue

            sev = Severity.LOW if status in (200, 201, 301, 302) else Severity.INFO
            if status == 500:
                sev = Severity.MEDIUM

            findings.append(Finding(
                title=f"[{status}] {url}",
                severity=sev,
                description=f"Content discovered: {url} (HTTP {status}, {item.get('content_length', 0)} bytes)",
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
