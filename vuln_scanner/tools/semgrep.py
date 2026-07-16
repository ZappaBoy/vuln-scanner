import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_CONFIG: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--config", "p/security-audit"],
    ScanMode.PASSIVE:  ["--config", "p/security-audit"],
    ScanMode.ACTIVE:   ["--config", "auto"],
    ScanMode.AGGRESSIVE: ["--config", "auto", "--config", "p/owasp-top-ten",
                          "--config", "p/cwe-top-25"],
}


class SemgrepTool(AbstractTool):
    name: str = "semgrep"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "."
        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore"]
        cmd += _MODE_CONFIG.get(scan_input.mode, _MODE_CONFIG[ScanMode.ACTIVE])
        cmd += scan_input.extra_args
        cmd.append(path)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            sev_label = (r.get("extra", {}).get("severity") or meta.get("impact") or "warning")
            severity = _parse_severity(sev_label)
            filepath = r.get("path", target)
            line = r.get("start", {}).get("line", "?")
            cves = [c for c in meta.get("cves", []) if c.startswith("CVE-")]
            refs = meta.get("references", [])
            findings.append(Finding(
                title=f"[{r.get('check_id', '?')}] {filepath}:{line}",
                severity=severity,
                description=r.get("extra", {}).get("message", ""),
                tool=self.name,
                target=filepath,
                cve=cves,
                references=refs,
                raw=r,
            ))

        return findings
