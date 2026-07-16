import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_XSS_RE = re.compile(r"XSS\s+Found\s+In\s+(.+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"(?:parameter|param)[:\s]+([^\s,]+)", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"(?:payload|vector)[:\s]+(.+)", re.IGNORECASE)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class XSStrikeTool(AbstractTool):
    name: str = "xsstrike"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["xsstrike", "-u", target, "--skip", "--timeout", "10"]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["--crawl"]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--blind"]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        # Strip ANSI escape codes from Rich/colorama output
        clean = _ANSI_RE.sub("", raw)
        seen: set[str] = set()

        lines = clean.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = _XSS_RE.search(line)
            if m:
                location = m.group(1).strip()
                # Try to gather payload from next few lines
                payload = ""
                param = ""
                for j in range(i + 1, min(i + 6, len(lines))):
                    next_line = lines[j].strip()
                    pm = _PARAM_RE.search(next_line)
                    plm = _PAYLOAD_RE.search(next_line)
                    if pm:
                        param = pm.group(1)
                    if plm:
                        payload = plm.group(1)

                key = f"{location}:{param}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"XSS in {location}" + (f" (param: {param})" if param else ""),
                        severity=Severity.HIGH,
                        description=(
                            f"Cross-Site Scripting vulnerability found in '{location}' on {target}."
                            + (f"\nParameter: {param}" if param else "")
                            + (f"\nPayload: {payload}" if payload else "")
                        ),
                        tool=self.name,
                        target=target,
                        raw={"location": location, "param": param, "payload": payload},
                    ))
            i += 1

        return findings
