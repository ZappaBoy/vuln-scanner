import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class DalfoxTool(AbstractTool):
    name: str = "dalfox"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["dalfox", "url", "--url", target, "--format", "json", "--silence"]

        if scan_input.mode == ScanMode.PARANOID:
            cmd += ["--only-discovery"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--deep-domxss", "--follow-redirects"]

        if scan_input.rate_limit is not None:
            cmd += ["--delay", str(max(0, 1000 // scan_input.rate_limit))]  # ms between reqs

        auth = scan_input.auth
        if auth.is_configured:
            if auth.cookie_string:
                cmd += ["--cookie", auth.cookie_string]
            for k, v in auth.headers.items():
                cmd += ["--header", f"{k}: {v}"]
            if auth.bearer_token and "Authorization" not in auth.headers:
                cmd += ["--header", f"Authorization: Bearer {auth.bearer_token}"]

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
