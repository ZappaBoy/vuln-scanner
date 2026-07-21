import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class DalfoxTool(AbstractTool):
    name: str = "dalfox"
    binary: str = "dalfox"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["dalfox", "scan", target, "-f", "jsonl", "-S", "--no-color"]

        if scan_input.mode == ScanMode.PARANOID:
            cmd += ["--only-discovery"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--deep-scan", "-F"]

        if scan_input.rate_limit is not None:
            cmd += ["--rate-limit", str(scan_input.rate_limit)]

        auth = scan_input.auth
        if auth.is_configured:
            if auth.cookie_string:
                cmd += ["--cookies", auth.cookie_string]
            for k, v in auth.headers.items():
                cmd += ["-H", f"{k}: {v}"]
            if auth.bearer_token and "Authorization" not in auth.headers:
                cmd += ["-H", f"Authorization: Bearer {auth.bearer_token}"]

        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []

        # dalfox may output one JSON object per line or a JSON array
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            cve = item.get("cve", "")
            poc = item.get("poc", item.get("payload", ""))
            param = item.get("param", "")
            evidence = item.get("evidence", "")
            severity_raw = item.get("severity", "medium").lower()

            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            sev = sev_map.get(severity_raw, Severity.MEDIUM)

            title = f"XSS in parameter '{param}'" if param else f"XSS: {poc[:80]}"
            findings.append(Finding(
                title=title,
                severity=sev,
                description=(
                    f"Cross-Site Scripting vulnerability detected on {target}.\n"
                    f"Parameter: {param}\nPoC: {poc}"
                    + (f"\nEvidence: {evidence}" if evidence else "")
                ),
                tool=self.name,
                target=target,
                cve=[cve] if cve else [],
                raw=item,
            ))

        return findings
