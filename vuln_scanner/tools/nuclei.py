import json

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    Severity,
    _as_url,
    _parse_severity,
)

_MODE_TEMPLATES: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["-t", "dns,ssl,http/technologies,http/headers", "-passive"],
    ScanMode.PASSIVE:  ["-t", "dns,ssl,http/technologies,http/headers,http/misconfiguration", "-passive"],
    ScanMode.ACTIVE:   ["-severity", "info,low,medium,high,critical"],
    ScanMode.AGGRESSIVE: ["-severity", "info,low,medium,high,critical", "-headless"],
}


class NucleiTool(AbstractTool):
    name: str = "nuclei"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["nuclei", "-u", _as_url(target), "-json", "-no-interactsh"]
        cmd += _MODE_TEMPLATES.get(scan_input.mode, [])
        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]
        cmd += ["-timeout", str(max(5, scan_input.timeout // 10))]
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

            info = item.get("info", {})
            severity = _parse_severity(info.get("severity", "info"))
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            cve = [r for r in refs if "CVE-" in r.upper()]

            findings.append(Finding(
                title=info.get("name", item.get("template-id", "Unknown")),
                severity=severity,
                description=info.get("description", "")
                            or f"Matched at {item.get('matched-at', target)}",
                tool=self.name,
                target=item.get("host", target),
                cve=cve,
                references=refs,
                raw=item,
            ))
        return findings
