import json

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_WORDLISTS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "/usr/share/wordlists/dirb/small.txt",
    ScanMode.PASSIVE:    "/usr/share/wordlists/dirb/common.txt",
    ScanMode.ACTIVE:     "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ScanMode.AGGRESSIVE: "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
}


class WfuzzTool(AbstractTool):
    name: str = "wfuzz"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target.rstrip("/")
        wordlist = _WORDLISTS[scan_input.mode]
        cmd = [
            "wfuzz",
            "-z", f"file,{wordlist}",
            "--hc", "404",
            "--color", "off",
            "-f", "-,json",  # stdout JSON
            f"{url}/FUZZ",
        ]
        if scan_input.rate_limit is not None:
            cmd += ["-t", str(min(scan_input.rate_limit, 40))]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # wfuzz JSON: array of result objects
        try:
            results = json.loads(raw)
        except json.JSONDecodeError:
            results = []

        if isinstance(results, dict):
            results = results.get("results", [])

        for item in results:
            code = item.get("code", 0)
            url = item.get("url", "")
            lines = item.get("lines", 0)
            words = item.get("words", 0)

            if not url or code == 404:
                continue

            sev = Severity.LOW if code in (200, 201) else Severity.INFO
            if code == 500:
                sev = Severity.MEDIUM

            findings.append(Finding(
                title=f"[{code}] {url}",
                severity=sev,
                description=f"Resource discovered: {url} (HTTP {code}, {lines} lines, {words} words)",
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings
