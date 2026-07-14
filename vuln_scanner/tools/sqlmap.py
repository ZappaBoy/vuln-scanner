import re

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_LEVEL_RISK: dict[ScanMode, tuple[int, int]] = {
    ScanMode.PARANOID:   (1, 1),
    ScanMode.PASSIVE:    (1, 1),
    ScanMode.ACTIVE:     (2, 1),
    ScanMode.AGGRESSIVE: (5, 3),
}

# Match lines like: Parameter: id (GET) appears to be 'MySQL >= 5.0 ...' injectable
_INJECT_RE = re.compile(
    r"Parameter:\s+(.+?)\s+\((\w+)\).+?appears to be '(.+?)' injectable",
    re.IGNORECASE,
)
# Match: [CRITICAL] parameter 'X' is vulnerable
_VULN_RE = re.compile(
    r"\[(CRITICAL|WARNING|INFO)\].*?(?:parameter|'([^']+)').*?(?:vulnerable|injectable)",
    re.IGNORECASE,
)


class SQLMapTool(AbstractTool):
    name: str = "sqlmap"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        level, risk = _LEVEL_RISK[scan_input.mode]
        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--smart",
            "--forms",
            f"--level={level}",
            f"--risk={risk}",
            "--output-dir=/tmp/vs_sqlmap",
        ]
        if scan_input.mode in (ScanMode.PASSIVE, ScanMode.PARANOID):
            cmd += ["--technique=B"]   # boolean-based only (least intrusive)
        if scan_input.rate_limit is not None:
            cmd += [f"--delay={max(1, 1 // scan_input.rate_limit)}"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            m = _INJECT_RE.search(line)
            if m:
                param, method, technique = m.group(1).strip(), m.group(2), m.group(3)
                key = f"{param}:{method}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    title=f"SQL injection: {method} parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Parameter '{param}' ({method}) on {target} is injectable "
                        f"via '{technique}'."
                    ),
                    tool=self.name,
                    target=target,
                    raw={"parameter": param, "method": method, "technique": technique},
                ))

        # Catch CRITICAL lines not matched by the main pattern
        for line in raw.splitlines():
            if "[CRITICAL]" in line and "injectable" in line.lower():
                key = line.strip()
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"SQLMap: {line.strip()[:120]}",
                        severity=Severity.CRITICAL,
                        description=line.strip(),
                        tool=self.name,
                        target=target,
                        raw={"raw_line": line.strip()},
                    ))

        return findings
