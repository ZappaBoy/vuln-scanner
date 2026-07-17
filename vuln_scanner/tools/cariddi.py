import json

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url


class CariddiTool(AbstractTool):
    name: str = "cariddi"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["cariddi", "-s", "-json", "-u", _as_url(target)]
        if scan_input.mode in ("active", "aggressive"):
            cmd += ["-intensive"]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-headers", f"{k}: {v}"]
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
                if line.startswith("http"):
                    findings.append(Finding(
                        title=f"URL: {line[:100]}",
                        severity=Severity.INFO,
                        description=f"Crawled URL: {line}",
                        tool=self.name,
                        target=target,
                        raw={"url": line},
                    ))
                continue

            url = item.get("url", "")
            finding_type = item.get("type", "")
            if not url:
                continue

            sev = Severity.INFO
            if finding_type in ("secret", "credentials"):
                sev = Severity.HIGH
            elif finding_type in ("endpoint", "api"):
                sev = Severity.LOW

            findings.append(Finding(
                title=f"{finding_type or 'URL'}: {url[:100]}",
                severity=sev,
                description=f"Cariddi found: {url}" + (f" (type: {finding_type})" if finding_type else ""),
                tool=self.name,
                target=target,
                raw=item,
            ))
        return findings
