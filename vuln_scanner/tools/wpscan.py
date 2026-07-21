import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_MODE_ENUMERATE: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--enumerate", "p,t,u", "--detection-mode", "passive"],
    ScanMode.PASSIVE:  ["--enumerate", "p,t,u", "--detection-mode", "passive"],
    ScanMode.ACTIVE:   ["--enumerate", "vp,vt,u,cb,dbe", "--detection-mode", "mixed"],
    ScanMode.AGGRESSIVE: [
        "--enumerate", "ap,at,cb,dbe,u",
        "--plugins-detection", "aggressive",
        "--detection-mode", "aggressive",
    ],
}


class WPScanTool(AbstractTool):
    name: str = "wpscan"
    binary: str = "wpscan"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = [
            "wpscan",
            "--url", _as_url(target),
            "--format", "json",
            "--no-banner",
            "--request-timeout", str(max(10, scan_input.timeout // 10)),
        ]
        cmd += _MODE_ENUMERATE.get(scan_input.mode, [])
        if scan_input.rate_limit is not None:
            throttle_ms = max(1, 1000 // scan_input.rate_limit)
            cmd += ["--throttle", str(throttle_ms)]
        auth = scan_input.auth
        if auth.is_configured:
            if auth.username and auth.password:
                cmd += ["--http-auth", f"{auth.username}:{auth.password}"]
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
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []

        def _vuln(vuln: dict, context: str) -> Finding:
            refs = [r for r in vuln.get("references", {}).get("url", [])]
            cve = vuln.get("references", {}).get("cve", [])
            return Finding(
                title=vuln.get("title", "WordPress vulnerability"),
                severity=Severity.HIGH,
                description=f"{context}: {vuln.get('title','')}",
                tool=self.name,
                target=target,
                cve=[f"CVE-{c}" for c in cve],
                references=refs,
                raw=vuln,
            )

        # Core version vulns
        version = data.get("version") or {}
        for v in version.get("vulnerabilities", []):
            findings.append(_vuln(v, "WordPress core"))

        # Plugin vulns
        for slug, plugin in (data.get("plugins") or {}).items():
            for v in plugin.get("vulnerabilities", []):
                findings.append(_vuln(v, f"Plugin: {slug}"))

        # Theme vulns
        for slug, theme in (data.get("themes") or {}).items():
            for v in theme.get("vulnerabilities", []):
                findings.append(_vuln(v, f"Theme: {slug}"))

        # Interesting findings (misconfigs, exposed files)
        for item in data.get("interesting_findings", []):
            findings.append(Finding(
                title=item.get("to_s", item.get("type", "Interesting finding")),
                severity=Severity.LOW,
                description=item.get("to_s", "") + "\n" + item.get("url", ""),
                tool=self.name,
                target=target,
                references=item.get("references", {}).get("url", []),
                raw=item,
            ))

        return findings
