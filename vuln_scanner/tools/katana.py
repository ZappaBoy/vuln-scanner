import json

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_DEPTH: dict[ScanMode, int] = {
    ScanMode.PARANOID: 1, ScanMode.PASSIVE: 2,
    ScanMode.ACTIVE: 3,   ScanMode.AGGRESSIVE: 5,
}


class KatanaTool(AbstractTool):
    name: str = "katana"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = [
            "katana",
            "-u", url,
            "-json",
            "-silent",
            "-depth", str(_DEPTH[scan_input.mode]),
        ]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-js-crawl", "-known-files", "all", "-automatic-form-fill"]
        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]
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

            endpoint = item.get("request", {}).get("endpoint") or item.get("endpoint", "")
            method = item.get("request", {}).get("method", "GET")
            source = item.get("source", "")
            if not endpoint:
                continue

            findings.append(Finding(
                title=f"Endpoint: {method} {endpoint}",
                severity=Severity.INFO,
                description=f"Crawled endpoint: {method} {endpoint}"
                            + (f" (source: {source})" if source else ""),
                tool=self.name,
                target=target,
                raw=item,
            ))
        return findings
