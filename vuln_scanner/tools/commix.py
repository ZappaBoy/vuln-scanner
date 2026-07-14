import re

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_VULN_RE = re.compile(
    r"parameter\s+'?([^']+?)'?\s+(?:appears to be|is)\s+(?:vulnerable|injectable).+?'(.+?)'",
    re.IGNORECASE,
)
_FOUND_RE = re.compile(
    r"(?:found|vulnerable|injectable).+?(?:command injection|OS command)",
    re.IGNORECASE,
)
_TECHNIQUE_RE = re.compile(
    r"(?:via|using|through)\s+(?:the\s+)?'?([^'\n]+?)'?\s+technique",
    re.IGNORECASE,
)


class CommixTool(AbstractTool):
    name: str = "commix"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["commix", "--url", target, "--batch"]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            cmd += ["--technique=C"]   # classic only (least intrusive)
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--all-techniques", "--crawl=2"]

        if scan_input.rate_limit is not None:
            cmd += [f"--delay={max(1, 1 // scan_input.rate_limit)}"]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                param, technique = m.group(1).strip(), m.group(2).strip()
                key = f"{param}:{technique}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Command injection: parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"OS command injection via parameter '{param}' on {target} "
                            f"using '{technique}' technique."
                        ),
                        tool=self.name,
                        target=target,
                        raw={"parameter": param, "technique": technique},
                    ))
            elif _FOUND_RE.search(line):
                key = line.strip()
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Command injection detected: {line.strip()[:100]}",
                        severity=Severity.CRITICAL,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line.strip()},
                    ))

        return findings
