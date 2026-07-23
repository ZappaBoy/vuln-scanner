"""checksec — ELF/PE binary hardening checks (NX, PIE, RELRO, stack canary, ...)."""

import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_MITIGATIONS = {
    "relro": ("RELRO", "No RELRO", "Partial RELRO", "Full RELRO"),
    "canary": ("Stack canary", "No", None, "Yes"),
    "nx": ("NX (DEP)", "No", None, "Yes"),
    "pie": ("PIE", "No", "DSO", "Yes"),
    "fortify": ("Fortify", "No", None, "Yes"),
}


def _check_mitigation(
    label: str, value: str, no_val: str, partial_val: str | None, yes_val: str
) -> tuple[str, Severity] | None:
    """Return (description, severity) if the mitigation is absent or partial, else None."""
    v = str(value).lower()
    no = no_val.lower()
    yes = yes_val.lower()
    partial = partial_val.lower() if partial_val else None

    if v == no or "no" in v and yes not in v:
        return f"{label} is disabled — binary lacks this exploit mitigation.", Severity.HIGH
    if partial and v == partial:
        return f"{label} is only partial — consider enabling full {label}.", Severity.LOW
    return None


class ChecksecTool(AbstractTool):
    name: str = "checksec"
    binary: str = "checksec"
    category: str = "binary"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["checksec", "--format=json", f"--file={target}"]
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

        # checksec JSON: {"/path/to/binary": {"relro": "full", "canary": "yes", ...}}
        binaries = data if isinstance(data, dict) else {}
        for binary_path, props in binaries.items():
            if not isinstance(props, dict):
                continue

            for key, (label, no_val, partial_val, yes_val) in _MITIGATIONS.items():
                value = props.get(key, "")
                if not value:
                    continue
                result = _check_mitigation(label, value, no_val, partial_val, yes_val)
                if result:
                    desc, sev = result
                    findings.append(
                        Finding(
                            title=f"Missing mitigation ({label}) in {binary_path}",
                            severity=sev,
                            description=(f"{desc}\nBinary: {binary_path}\nCurrent value: {value}"),
                            tool=self.name,
                            target=target,
                            cwe=["CWE-693"],
                            raw={"binary": binary_path, "property": key, "value": value},
                        )
                    )

        return findings
