from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    OUTPUT_FILE_SENTINEL,
    ScanInput,
    ScanMode,
    ScanResult,
    Severity,
)


class ParamSpiderTool(AbstractTool):
    name: str = "paramspider"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target should be a domain (e.g. example.com) — paramspider queries web archives
        domain = (
            target.replace("https://", "").replace("http://", "").split("/")[0]
        )
        cmd = ["paramspider", "-d", domain, "--output", OUTPUT_FILE_SENTINEL, "--quiet"]

        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--subs"]   # include subdomains

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

            # URLs with parameters are interesting for injection testing
            has_params = "?" in url and "=" in url
            sev = Severity.INFO

            findings.append(Finding(
                title=f"Parameterised URL: {url[:120]}",
                severity=sev,
                description=f"URL with parameters discovered from web archives: {url}",
                tool=self.name,
                target=target,
                raw={"url": url, "has_params": has_params},
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".txt")
