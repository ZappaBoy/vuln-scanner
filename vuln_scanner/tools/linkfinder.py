from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url


class LinkFinderTool(AbstractTool):
    name: str = "linkfinder"
    binary: str = "linkfinder"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["linkfinder", "-i", _as_url(target), "-o", "cli"]
        if scan_input.mode in ("active", "aggressive"):
            cmd += ["-d"]  # domain crawl mode
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Filter out obvious non-endpoints
            if line.startswith("http") or line.startswith("/") or "." in line.split("/")[0]:
                key = line
                if key in seen:
                    continue
                seen.add(key)
                sev = Severity.INFO
                low = line.lower()
                if "api" in low or "admin" in low or "secret" in low or "token" in low or "key" in low:
                    sev = Severity.LOW
                findings.append(Finding(
                    title=f"Endpoint discovered: {line[:100]}",
                    severity=sev,
                    description=f"Endpoint found in JavaScript/HTML source: {line}",
                    tool=self.name,
                    target=target,
                    raw={"endpoint": line},
                ))
        return findings
