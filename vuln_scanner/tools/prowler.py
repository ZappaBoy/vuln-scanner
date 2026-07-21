import json

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_MODE_ARGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID:   ["-g", "cislevel1"],
    ScanMode.PASSIVE:    ["-g", "cislevel1"],
    ScanMode.ACTIVE:     ["-g", "cislevel2"],
    ScanMode.AGGRESSIVE: [],  # all checks
}


class ProwlerTool(AbstractTool):
    name: str = "prowler"
    binary: str = "prowler"
    category: str = "cloud"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["prowler", "-M", "json-asff", "--output-directory", "/tmp/vs_prowler"]
        # target may be "aws:profile=myprofile" or "arn:aws:..."
        if target.startswith("aws:"):
            suffix = target[4:]
            if suffix.startswith("profile="):
                cmd += ["--profile", suffix[8:]]
        cmd += _MODE_ARGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            status = item.get("Status", "")
            if status.upper() == "PASS":
                continue

            severity_raw = item.get("Severity", {}).get("Label", "medium")
            sev = _parse_severity(severity_raw)
            title = item.get("Title", item.get("CheckID", "AWS finding"))
            desc = item.get("Description", "")
            region = item.get("Resources", [{}])[0].get("Region", "") if item.get("Resources") else ""
            resource = item.get("Resources", [{}])[0].get("Id", target) if item.get("Resources") else target

            rec_url = item.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
            findings.append(Finding(
                title=title,
                severity=sev,
                description=f"{desc}\nResource: {resource}" + (f"\nRegion: {region}" if region else ""),
                tool=self.name,
                target=target,
                references=[rec_url] if rec_url else [],
                raw=item,
            ))
        return findings
