import json

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_SEV_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "CRITICAL": Severity.CRITICAL,
}


class GraphQLCopTool(AbstractTool):
    name: str = "graphql-cop"
    binary: str = "graphql-cop"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = ["graphql-cop", "-t", url, "-o", "json"]

        if scan_input.mode == ScanMode.PASSIVE:
            cmd += ["--introspection"]  # only run introspection-based checks
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--dos"]  # include denial-of-service checks

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
        results = data if isinstance(data, list) else data.get("results", [])

        for item in results:
            result_flag = item.get("result", False)
            if not result_flag:
                continue

            title = item.get("title", item.get("name", "GraphQL issue"))
            impact = item.get("impact", "")
            description = item.get("description", "")
            severity_raw = item.get("severity", "MEDIUM").upper()
            sev = _SEV_MAP.get(severity_raw, Severity.MEDIUM)

            findings.append(
                Finding(
                    title=f"GraphQL: {title}",
                    severity=sev,
                    description=((description or title) + (f"\nImpact: {impact}" if impact else "")),
                    tool=self.name,
                    target=target,
                    raw=item,
                )
            )

        return findings
