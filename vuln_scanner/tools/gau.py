from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class GauTool(AbstractTool):
    name: str = "gau"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = ["gau", domain]

        providers = ["wayback", "commoncrawl", "otx"]
        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            providers = ["wayback"]
        cmd += ["--providers", ",".join(providers)]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--subs"]

        if scan_input.rate_limit is not None:
            cmd += ["--threads", str(min(scan_input.rate_limit, 20))]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)

            findings.append(Finding(
                title=f"Archived URL: {url[:120]}",
                severity=Severity.INFO,
                description=f"URL found in web archives for {target}: {url}",
                tool=self.name,
                target=target,
                raw={"url": url},
            ))

        return findings
