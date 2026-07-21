"""h2csmuggler — HTTP/2 cleartext (h2c) request smuggling scanner."""
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

# "[INFO] Found h2c server at https://target.com"
# "h2c streaming request is VULNERABLE: https://target.com"
# "[*] VULNERABLE: ..."
_VULN_RE = re.compile(
    r"(?:VULNERABLE|vulnerable|h2c.*smuggling|h2c.*possible)[:\s]+(?P<detail>.+)",
    re.IGNORECASE,
)
_H2C_RE = re.compile(r"Found\s+h2c\s+server\s+at\s+(?P<url>https?://\S+)", re.IGNORECASE)


class H2cSmugglerTool(AbstractTool):
    name: str = "h2csmuggler"
    binary: str = "h2csmuggler"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["h2csmuggler", "--scan-list", url]

        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]

        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        h2c_urls: list[str] = []
        for m in _H2C_RE.finditer(raw):
            h2c_urls.append(m.group("url"))

        for m in _VULN_RE.finditer(raw):
            detail = m.group("detail").strip()
            findings.append(Finding(
                title=f"HTTP/2 cleartext smuggling (h2c) at {target}",
                severity=Severity.HIGH,
                description=(
                    f"h2csmuggler detected HTTP/2 cleartext upgrade smuggling vulnerability.\n"
                    f"Detail: {detail}\n"
                    f"An attacker can bypass front-end security controls by smuggling requests "
                    f"over an h2c upgrade to the back-end server."
                ),
                tool=self.name,
                target=target,
                cwe=["CWE-444"],
                raw={"detail": detail, "h2c_endpoints": h2c_urls},
            ))

        # If h2c endpoints found but no explicit vuln marker, report as info
        if h2c_urls and not findings:
            for url in h2c_urls:
                findings.append(Finding(
                    title=f"h2c upgrade server detected at {url}",
                    severity=Severity.LOW,
                    description=(
                        f"An HTTP/2 cleartext (h2c) upgrade endpoint was detected at {url}. "
                        f"This may be exploitable for request smuggling depending on proxy configuration."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-444"],
                    raw={"url": url},
                ))

        return findings
