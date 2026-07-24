import re

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

# "https://example.com - Origin: https://evil.com - is allowed"
_ALLOWED_RE = re.compile(
    r"(https?://\S+)\s+-\s+Origin:\s+(\S+)\s+-\s+is allowed",
    re.IGNORECASE,
)
_VULN_RE = re.compile(r"(Vulnerable|CORS misconfiguration|arbitrary origin)", re.IGNORECASE)

_SEVERITY_KEYWORDS: dict[str, Severity] = {
    "null": Severity.HIGH,  # null origin allowed
    "reflected": Severity.HIGH,  # reflected arbitrary origin
    "wildcard": Severity.MEDIUM,  # Access-Control-Allow-Origin: *
    "trusted": Severity.LOW,
    "is allowed": Severity.MEDIUM,
}


class CORScannerTool(AbstractTool):
    name: str = "corscanner"
    binary: str = "corscanner"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.LIVE_HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["corscanner", "-u", url]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-t", "20"]  # more threads
        elif scan_input.mode in (ScanMode.ACTIVE,):
            cmd += ["-t", "5"]

        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]

        if scan_input.proxy:
            cmd += ["-p", scan_input.proxy]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _ALLOWED_RE.search(line)
            if m:
                url, origin = m.group(1), m.group(2)
                key = f"{url}:{origin}"
                if key in seen:
                    continue
                seen.add(key)

                sev = Severity.MEDIUM
                low = line.lower()
                if "null" in low:
                    sev = Severity.HIGH
                elif "wildcard" in low or "*" in origin:
                    sev = Severity.MEDIUM

                findings.append(
                    Finding(
                        title=f"CORS: origin '{origin}' allowed on {url}",
                        severity=sev,
                        description=(
                            f"CORS misconfiguration: origin '{origin}' is reflected/allowed "
                            f"by {url}. This may allow cross-origin requests from untrusted origins."
                        ),
                        tool=self.name,
                        target=url,
                        raw={"url": url, "origin": origin, "raw_line": line},
                    )
                )
                continue

            if _VULN_RE.search(line):
                key = line
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            title=f"CORS issue: {line[:100]}",
                            severity=Severity.MEDIUM,
                            description=line,
                            tool=self.name,
                            target=target,
                            raw={"raw_line": line},
                        )
                    )

        return findings
