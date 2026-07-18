import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_SEV_BY_STATUS = {
    range(200, 300): Severity.INFO,
    range(300, 400): Severity.INFO,
    range(400, 500): Severity.LOW,
    range(500, 600): Severity.MEDIUM,
}


def _status_severity(code: int) -> Severity:
    for r, sev in _SEV_BY_STATUS.items():
        if code in r:
            return sev
    return Severity.INFO


class HttpxTool(AbstractTool):
    name: str = "httpx"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["httpx", "-u", target, "-json", "-silent", "-status-code", "-title", "-tech-detect"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-follow-redirects", "-content-length", "-web-server", "-ip"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-screenshot", "-tls-grab"]

        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]

        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]

        if scan_input.proxy:
            cmd += ["-http-proxy", scan_input.proxy]
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

            url = item.get("url", target)
            status = item.get("status_code", 0)
            title = item.get("title", "")
            server = item.get("webserver", "")
            techs = item.get("tech", [])
            _ = item.get("content_length", 0)  # noqa: F841

            desc_parts = [f"URL: {url}", f"Status: {status}"]
            if title:
                desc_parts.append(f"Title: {title}")
            if server:
                desc_parts.append(f"Server: {server}")
            if techs:
                desc_parts.append(f"Technologies: {', '.join(techs)}")

            findings.append(Finding(
                title=f"[{status}] {url}" + (f" — {title}" if title else ""),
                severity=_status_severity(status),
                description="\n".join(desc_parts),
                tool=self.name,
                target=target,
                raw=item,
            ))
        return findings
