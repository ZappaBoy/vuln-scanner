import json

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity


class DnsxTool(AbstractTool):
    name: str = "dnsx"
    category: str = "network"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        cmd = ["dnsx", "-d", target, "-json", "-silent", "-resp"]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            # query all common record types
            cmd += ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-srv"]
        elif scan_input.mode in (ScanMode.ACTIVE, ScanMode.PASSIVE):
            cmd += ["-a", "-cname", "-mx", "-ns"]
        # paranoid: only A records (default)

        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = item.get("host", "")
            status_code = item.get("status_code", "")
            resolver = item.get("resolver", [])

            all_records: list[str] = []
            for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt", "srv"):
                records = item.get(rtype, [])
                if records:
                    all_records.append(f"{rtype.upper()}: {', '.join(records)}")

            findings.append(Finding(
                title=f"DNS: {host} ({status_code})",
                severity=Severity.INFO,
                description=(
                    f"DNS record for {host}: status={status_code}, "
                    + ("; ".join(all_records) or "no records")
                    + (f", resolver={resolver}" if resolver else "")
                ),
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings
