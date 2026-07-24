import re

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_WORDLISTS: dict[ScanMode, str] = {
    ScanMode.PARANOID: "/usr/share/wordlists/kiterunner/routes-small.kite",
    ScanMode.PASSIVE: "/usr/share/wordlists/kiterunner/routes-small.kite",
    ScanMode.ACTIVE: "/usr/share/wordlists/kiterunner/routes-large.kite",
    ScanMode.AGGRESSIVE: "/usr/share/wordlists/kiterunner/routes-large.kite",
}

# "POST   200 [   312,    8,    2] https://example.com/api/v1/users 0ms"
_ROUTE_RE = re.compile(r"(\w+)\s+(\d{3})\s+\[\s*(\d+),\s*(\d+),\s*(\d+)\]\s+(\S+)")

_STATUS_SEV: dict[int, Severity] = {
    200: Severity.LOW,
    201: Severity.LOW,
    204: Severity.LOW,
    401: Severity.INFO,
    403: Severity.INFO,
    500: Severity.MEDIUM,
}


class KiterunnerTool(AbstractTool):
    name: str = "kiterunner"
    binary: str = "kiterunner"
    category: str = "api"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        wordlist = _WORDLISTS[scan_input.mode]
        cmd = [
            "kiterunner",
            "scan",
            url,
            "-w",
            wordlist,
            "--fail-status-codes",
            "404",
            "--ignore-length",
            "0",
            "-o",
            "text",
            "-q",
        ]
        if scan_input.rate_limit is not None:
            cmd += ["-x", str(min(scan_input.rate_limit, 20))]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            m = _ROUTE_RE.search(line.strip())
            if not m:
                continue
            method, status_str, length, words, _, url = (
                m.group(1),
                m.group(2),
                m.group(3),
                m.group(4),
                m.group(5),
                m.group(6),
            )
            status = int(status_str)
            key = f"{method}:{url}"
            if key in seen:
                continue
            seen.add(key)

            sev = _STATUS_SEV.get(status, Severity.INFO)
            findings.append(
                Finding(
                    title=f"API route: {method} {url} [{status}]",
                    severity=sev,
                    description=(
                        f"API route discovered: {method} {url} (HTTP {status}, {length} bytes, {words} words)"
                    ),
                    tool=self.name,
                    target=target,
                    raw={"method": method, "status": status, "url": url, "length": length},
                )
            )

        return findings
