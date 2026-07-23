"""nomore403 — automated 403/40x restriction bypass tool."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

# "[200] https://target.com/admin with header: X-Original-URL: /"
# "BYPASS FOUND: https://target.com/admin via ..."
_BYPASS_RE = re.compile(
    r"\[(?P<code>2\d{2})\]\s+(?P<url>https?://\S+)"
    r"(?:\s+(?:with|via)\s+(?P<method>.+))?",
    re.IGNORECASE,
)
_BYPASS_BANNER = re.compile(r"BYPASS\s+FOUND", re.IGNORECASE)


class Nomore403Tool(AbstractTool):
    name: str = "nomore403"
    binary: str = "nomore403"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["nomore403", "-u", url]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--techniques", "all"]

        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
            if auth.cookie_string:
                cmd += ["--cookie", auth.cookie_string]

        if scan_input.proxy:
            cmd += ["-x", scan_input.proxy]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            m = _BYPASS_RE.search(line)
            if not m:
                continue
            code = m.group("code")
            url = m.group("url")
            method = (m.group("method") or "").strip()
            key = f"{url}:{method}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    title=f"403 bypass [{code}]: {url}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"nomore403 bypassed a 403 restriction on {url} "
                        f"(returned HTTP {code})." + (f"\nBypass technique: {method}" if method else "")
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-284"],
                    raw={"url": url, "status": code, "technique": method},
                )
            )

        return findings
