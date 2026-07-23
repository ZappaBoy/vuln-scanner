import json

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_AGGRESSION: dict[ScanMode, int] = {
    ScanMode.PARANOID: 1,
    ScanMode.PASSIVE: 1,
    ScanMode.ACTIVE: 2,
    ScanMode.AGGRESSIVE: 3,
}

# Technologies that should flag at least INFO
_INTERESTING = {
    "PHP",
    "WordPress",
    "Drupal",
    "Joomla",
    "Apache",
    "Nginx",
    "IIS",
    "jQuery",
    "Bootstrap",
    "Ruby on Rails",
    "Django",
}


class WhatWebTool(AbstractTool):
    name: str = "whatweb"
    binary: str = "whatweb"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST, TargetType.IP})
    produces: frozenset[AssetType] = frozenset({AssetType.TECH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        aggression = _AGGRESSION[scan_input.mode]
        cmd = [
            "whatweb",
            "--log-json=-",
            f"--aggression={aggression}",
            "--quiet",
            "--no-errors",
            "--open-timeout=10",
            "--read-timeout=10",
            "--max-threads=5",
            url,
        ]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("["):
                continue
            try:
                items = json.loads(line)
                if not isinstance(items, list):
                    items = [items]
            except json.JSONDecodeError:
                continue

            for item in items:
                url = item.get("target", target)
                plugins = item.get("plugins", {})
                http_status = item.get("http_status", 0)

                for tech, details in plugins.items():
                    version_list = details.get("version", [])
                    string_list = details.get("string", [])
                    version = ", ".join(str(v) for v in version_list) if version_list else ""
                    strings = ", ".join(str(s) for s in string_list) if string_list else ""

                    label = tech
                    if version:
                        label += f" {version}"

                    sev = Severity.INFO
                    # Version disclosure of known techs is low-severity finding
                    if version and tech in _INTERESTING:
                        sev = Severity.LOW

                    findings.append(
                        Finding(
                            title=f"Technology detected: {label}",
                            severity=sev,
                            description=(
                                f"Detected '{label}' on {url} (HTTP {http_status})"
                                + (f": {strings}" if strings else "")
                            ),
                            tool=self.name,
                            target=url,
                            raw={"tech": tech, "version": version, "details": details},
                        )
                    )

        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        assets = []
        for f in result.findings:
            tech = f.raw.get("tech", "")
            version = f.raw.get("version", "")
            if tech:
                value = f"{tech}:{version}" if version else tech
                assets.append(
                    Asset(
                        type=AssetType.TECH,
                        value=value,
                        source=self.name,
                        target=result.target,
                        meta={"version": version} if version else {},
                    )
                )
        return assets
