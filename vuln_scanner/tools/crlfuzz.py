from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class CRLFuzzTool(AbstractTool):
    name: str = "crlfuzz"
    binary: str = "crlfuzz"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["crlfuzz", "-u", _as_url(target), "-s"]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # crlfuzz prints vulnerable URLs with "[VULN]" or just the URL
            if "[VULN]" in line or "carriage return" in line.lower() or "crlf" in line.lower():
                url = line.replace("[VULN]", "").strip()
                findings.append(
                    Finding(
                        title=f"CRLF Injection: {url[:120]}",
                        severity=Severity.HIGH,
                        description=(
                            f"CRLF injection vulnerability detected at {url}.\n"
                            "An attacker may inject arbitrary HTTP headers or split responses."
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-93"],
                        raw={"url": url, "raw_line": line},
                    )
                )
        return findings
