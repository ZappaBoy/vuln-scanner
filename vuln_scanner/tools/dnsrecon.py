import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL

_TYPE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID:   ["-t", "std"],
    ScanMode.PASSIVE:    ["-t", "std"],
    ScanMode.ACTIVE:     ["-t", "std,brt,axfr"],
    ScanMode.AGGRESSIVE: ["-t", "std,brt,axfr,bing,yandex"],
}


class DNSReconTool(AbstractTool):
    name: str = "dnsrecon"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["dnsrecon", "-d", target, "-j", OUTPUT_FILE_SENTINEL]
        cmd += _TYPE_FLAGS.get(scan_input.mode, ["-t", "std"])

        if scan_input.rate_limit is not None:
            cmd += ["--lifetime", str(max(1, 60 // scan_input.rate_limit))]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        # dnsrecon writes a list of record objects
        if isinstance(data, dict):
            records = data.get("records", [])
        else:
            records = data if isinstance(data, list) else []

        findings: list[Finding] = []
        for record in records:
            rtype = record.get("type", "?")
            name = record.get("name", record.get("target", ""))
            address = record.get("address", record.get("address", ""))

            if rtype == "info":
                continue

            title = f"DNS {rtype}: {name}"
            if address:
                title += f" → {address}"

            sev = Severity.HIGH if rtype in ("AXFR",) else Severity.INFO
            findings.append(Finding(
                title=title,
                severity=sev,
                description=f"DNS record discovered: {json.dumps(record)}",
                tool=self.name,
                target=target,
                raw=record,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
