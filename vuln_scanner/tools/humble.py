import json
import re

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

# Security headers whose absence is a finding
_MISSING_HEADER_SEV: dict[str, Severity] = {
    "Strict-Transport-Security":        Severity.HIGH,
    "Content-Security-Policy":          Severity.MEDIUM,
    "X-Content-Type-Options":           Severity.MEDIUM,
    "X-Frame-Options":                  Severity.MEDIUM,
    "Permissions-Policy":               Severity.LOW,
    "Referrer-Policy":                  Severity.LOW,
    "Cross-Origin-Embedder-Policy":     Severity.LOW,
    "Cross-Origin-Opener-Policy":       Severity.LOW,
    "Cross-Origin-Resource-Policy":     Severity.LOW,
    "Cache-Control":                    Severity.LOW,
}

# Deprecated / dangerous headers
_DEPRECATED_SEV: dict[str, Severity] = {
    "X-XSS-Protection":            Severity.LOW,
    "X-Powered-By":                Severity.LOW,
    "Server":                      Severity.LOW,
    "X-AspNet-Version":            Severity.LOW,
    "X-AspNetMvc-Version":         Severity.LOW,
    "Feature-Policy":              Severity.LOW,
    "Expect-CT":                   Severity.LOW,
    "Public-Key-Pins":             Severity.LOW,
    "Public-Key-Pins-Report-Only": Severity.LOW,
}


class HumbleTool(AbstractTool):
    name: str = "humble"
    category: str = "ssl"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["humble", "-u", url, "-j"]  # JSON output

        if scan_input.mode in (ScanMode.PASSIVE, ScanMode.PARANOID):
            cmd += ["-g"]   # skip the fingerprinting requests

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        # Try JSON first (humble -j)
        try:
            data = json.loads(raw)
            return self._parse_json(data, target)
        except (json.JSONDecodeError, ValueError):
            pass

        # Fall back to text output parsing
        return self._parse_text(raw, target)

    def _parse_json(self, data: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []

        missing = data.get("missing_headers") or data.get("missing") or []
        for header in missing:
            name = header if isinstance(header, str) else header.get("header", str(header))
            sev = _MISSING_HEADER_SEV.get(name, Severity.INFO)
            findings.append(Finding(
                title=f"Missing security header: {name}",
                severity=sev,
                description=f"HTTP response is missing the '{name}' security header.",
                tool=self.name,
                target=target,
                raw={"missing_header": name},
            ))

        deprecated = data.get("deprecated_headers") or data.get("deprecated") or []
        for header in deprecated:
            name = header if isinstance(header, str) else header.get("header", str(header))
            sev = _DEPRECATED_SEV.get(name, Severity.INFO)
            findings.append(Finding(
                title=f"Deprecated/unsafe header: {name}",
                severity=sev,
                description=f"HTTP response includes deprecated/unsafe header '{name}'.",
                tool=self.name,
                target=target,
                raw={"deprecated_header": name},
            ))

        fingerprint = data.get("fingerprint") or {}
        for header, value in fingerprint.items():
            findings.append(Finding(
                title=f"Fingerprinting header: {header}",
                severity=Severity.LOW,
                description=f"Header '{header}: {value}' reveals technology details.",
                tool=self.name,
                target=target,
                raw={"header": header, "value": value},
            ))

        return findings

    def _parse_text(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        section = None

        for line in raw.splitlines():
            stripped = line.strip()
            low = stripped.lower()

            if "missing" in low and "header" in low:
                section = "missing"
                continue
            if "deprecated" in low or "unsafe" in low:
                section = "deprecated"
                continue
            if "fingerprint" in low:
                section = "fingerprint"
                continue
            if stripped.startswith("[") or stripped == "":
                section = None
                continue

            # Pick up header names (lines like "  - Strict-Transport-Security")
            header_match = re.match(r"[-*]\s+(.+)", stripped)
            if header_match and section:
                name = header_match.group(1).strip()
                if section == "missing":
                    sev = _MISSING_HEADER_SEV.get(name, Severity.INFO)
                    findings.append(Finding(
                        title=f"Missing security header: {name}",
                        severity=sev,
                        description=f"HTTP response is missing '{name}'.",
                        tool=self.name,
                        target=target,
                        raw={"missing_header": name},
                    ))
                elif section == "deprecated":
                    sev = _DEPRECATED_SEV.get(name, Severity.INFO)
                    findings.append(Finding(
                        title=f"Deprecated/unsafe header: {name}",
                        severity=sev,
                        description=f"HTTP response includes deprecated/unsafe header '{name}'.",
                        tool=self.name,
                        target=target,
                        raw={"deprecated_header": name},
                    ))
                elif section == "fingerprint":
                    findings.append(Finding(
                        title=f"Fingerprinting header: {name}",
                        severity=Severity.LOW,
                        description=f"Header '{name}' reveals technology details.",
                        tool=self.name,
                        target=target,
                        raw={"header": name},
                    ))

        return findings
