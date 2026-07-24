import json

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import OUTPUT_FILE_SENTINEL, AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult


class WafW00fTool(AbstractTool):
    name: str = "wafw00f"
    binary: str = "wafw00f"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST, TargetType.IP})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["wafw00f", url, "-o", OUTPUT_FILE_SENTINEL, "-f", "json"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-a"]  # test all WAFs even if one is detected
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings = []
        results = data if isinstance(data, list) else data.get("results", [data])

        for item in results:
            url = item.get("url", target)
            firewall = item.get("firewall", "")
            manufacturer = item.get("manufacturer", "")
            detected = item.get("detected", bool(firewall))

            if detected and firewall:
                label = firewall
                if manufacturer:
                    label += f" ({manufacturer})"
                findings.append(
                    Finding(
                        title=f"WAF detected: {label}",
                        severity=Severity.INFO,
                        description=(
                            f"Web Application Firewall detected on {url}: {label}. Adjust scan approach accordingly."
                        ),
                        tool=self.name,
                        target=url,
                        raw=item,
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="No WAF detected",
                        severity=Severity.INFO,
                        description=f"No WAF was detected on {url}.",
                        tool=self.name,
                        target=url,
                        raw=item,
                    )
                )

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
