from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput


class SmugglerTool(AbstractTool):
    name: str = "smuggler"
    binary: str = "smuggler"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["smuggler", "-u", _as_url(target), "--no-color"]
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
            low = line.lower()
            if "possible" in low or "vulnerable" in low or "issue found" in low or "cl.te" in low or "te.cl" in low:
                findings.append(
                    Finding(
                        title=f"HTTP Request Smuggling: {line[:100]}",
                        severity=Severity.HIGH,
                        description=(
                            f"Potential HTTP request smuggling vulnerability detected on {target}.\nDetail: {line}"
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-444"],
                        raw={"raw_line": line},
                    )
                )
        return findings
