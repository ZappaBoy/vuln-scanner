import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# SecretFinder output lines look like:
# [FOUND] Google API Key: AIzaSy...  in https://example.com/app.js
_FOUND_RE = re.compile(
    r"\[FOUND\]\s+(.+?):\s+(\S+)(?:\s+in\s+(\S+))?",
    re.IGNORECASE,
)

_SEV_BY_KIND: dict[str, Severity] = {
    "google api key":       Severity.HIGH,
    "aws access key":       Severity.CRITICAL,
    "private key":          Severity.CRITICAL,
    "firebase":             Severity.HIGH,
    "slack":                Severity.HIGH,
    "github":               Severity.HIGH,
    "stripe":               Severity.CRITICAL,
    "twilio":               Severity.HIGH,
    "jwt":                  Severity.MEDIUM,
    "bearer":               Severity.MEDIUM,
    "password":             Severity.HIGH,
    "secret":               Severity.HIGH,
    "token":                Severity.HIGH,
    "api key":              Severity.HIGH,
}


def _classify(kind: str) -> Severity:
    low = kind.lower()
    for keyword, sev in _SEV_BY_KIND.items():
        if keyword in low:
            return sev
    return Severity.MEDIUM


class SecretFinderTool(AbstractTool):
    name: str = "secretfinder"
    binary: str = "SecretFinder"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH, TargetType.REPO})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["SecretFinder", "-i", url, "-o", "cli"]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-e"]   # include all JS files linked from the page

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        clean = _ANSI_RE.sub("", raw)
        seen: set[str] = set()

        for line in clean.splitlines():
            line = line.strip()
            m = _FOUND_RE.search(line)
            if not m:
                continue

            kind = m.group(1).strip()
            value = m.group(2).strip()
            location = m.group(3) or target
            key = f"{kind}:{value}"

            if key in seen:
                continue
            seen.add(key)

            sev = _classify(kind)
            findings.append(Finding(
                title=f"Secret in JS: {kind}",
                severity=sev,
                description=(
                    f"Potential {kind} found in JavaScript at {location}.\n"
                    f"Value: {value[:120]}"
                ),
                tool=self.name,
                target=target,
                raw={"kind": kind, "value": value, "location": location},
            ))

        return findings
