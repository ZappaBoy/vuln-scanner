import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["-ll", "-ii"],                  # low confidence + low severity
    ScanMode.PASSIVE:  ["-l"],                          # low severity threshold
    ScanMode.ACTIVE:   [],                              # defaults
    ScanMode.AGGRESSIVE: ["-l", "-i"],                  # all severities, all confidence
}


class BanditTool(AbstractTool):
    name: str = "bandit"
    binary: str = "bandit"
    category: str = "sast"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})
    silent_flags: list[str] = ["-q"]
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        path = target if target.startswith("/") else "."
        cmd = ["bandit", "-r", path, "-f", "json", "-q",
               "--exclude", ".venv,venv,.git,node_modules,dist,build,tests",
               "--skip", "B101,B404,B405,B603"]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
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
        for r in data.get("results", []):
            severity = _parse_severity(r.get("issue_severity", "low"))
            filepath = r.get("filename", target)
            line = r.get("line_number", "?")
            cwe = r.get("issue_cwe", {})
            refs = [r.get("more_info", "")] if r.get("more_info") else []
            findings.append(Finding(
                title=f"[{r.get('test_id')}] {r.get('issue_text', 'Bandit finding')[:100]}",
                severity=severity,
                description=(
                    f"{r.get('issue_text', '')}\n"
                    f"File: {filepath}:{line}\n"
                    f"CWE: {cwe.get('id','?')} — {cwe.get('link','')}"
                ),
                tool=self.name,
                target=filepath,
                references=refs,
                raw=r,
            ))
        return findings
