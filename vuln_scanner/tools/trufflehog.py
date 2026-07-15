import json

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    Severity,
)

_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--only-verified"],
    ScanMode.PASSIVE:  ["--only-verified"],
    ScanMode.ACTIVE:   [],
    ScanMode.AGGRESSIVE: ["--include-detectors=all"],
}


class TrufflehogTool(AbstractTool):
    name: str = "trufflehog"
    category: str = "secrets"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # target: filesystem path or git repo URL
        if target.startswith(("http://", "https://", "git@")):
            subcommand = "git"
        else:
            subcommand = "filesystem"
            target = target if target.startswith("/") else "."

        cmd = ["trufflehog", subcommand, "--json", "--no-update",
               "--exclude-paths=.venv,.git,node_modules,dist,build"]
        cmd += _MODE_FLAGS.get(scan_input.mode, [])
        cmd += scan_input.extra_args
        cmd.append(target)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = item.get("DetectorName", item.get("detectorType", "unknown"))
            source = item.get("SourceMetadata", {})
            data = source.get("Data", {})
            filepath = (
                data.get("Filesystem", {}).get("file")
                or data.get("Git", {}).get("file")
                or target
            )
            verified = item.get("Verified", False)
            raw_str = item.get("Raw", "")

            findings.append(Finding(
                title=f"{'Verified secret' if verified else 'Potential secret'}: {detector}",
                severity=Severity.CRITICAL if verified else Severity.HIGH,
                description=(
                    f"Detector: {detector}\n"
                    f"File: {filepath}\n"
                    f"Verified: {verified}\n"
                    f"Raw (truncated): {raw_str[:80]}"
                ),
                tool=self.name,
                target=filepath or target,
                raw=item,
            ))
        return findings
