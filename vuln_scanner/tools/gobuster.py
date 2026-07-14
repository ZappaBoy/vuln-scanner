import re

from vuln_scanner.tools.base import AbstractTool, Finding, ScanInput, ScanMode, Severity

_WORDLISTS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "/usr/share/wordlists/dirb/small.txt",
    ScanMode.PASSIVE:    "/usr/share/wordlists/dirb/common.txt",
    ScanMode.ACTIVE:     "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ScanMode.AGGRESSIVE: "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
}

# "/admin (Status: 200) [Size: 1234]"
_LINE_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")


class GobusterTool(AbstractTool):
    name: str = "gobuster"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        wordlist = _WORDLISTS[scan_input.mode]
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-q",
            "--no-progress",
        ]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-x", "php,asp,aspx,jsp,html,txt,bak,old,zip"]
        if scan_input.rate_limit is not None:
            cmd += ["-t", str(min(scan_input.rate_limit, 50))]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            m = _LINE_RE.match(line)
            if not m:
                continue
            path, status_str, size_str = m.group(1), m.group(2), m.group(3) or "?"
            status = int(status_str)
            if status == 404:
                continue

            sev = Severity.INFO
            if status in (200, 201):
                sev = Severity.LOW
            elif status == 500:
                sev = Severity.MEDIUM

            findings.append(Finding(
                title=f"[{status}] {target}{path}",
                severity=sev,
                description=f"Directory/file found: {target}{path} (HTTP {status}, size {size_str})",
                tool=self.name,
                target=target,
                raw={"path": path, "status": status, "size": size_str},
            ))

        return findings
