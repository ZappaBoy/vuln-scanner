import json

from vuln_scanner.assets import Asset, AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_DEPTH: dict[ScanMode, int] = {
    ScanMode.PARANOID: 1,
    ScanMode.PASSIVE: 2,
    ScanMode.ACTIVE: 3,
    ScanMode.AGGRESSIVE: 5,
}


class KatanaTool(AbstractTool):
    name: str = "katana"
    binary: str = "katana"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    produces: frozenset[AssetType] = frozenset({AssetType.URL, AssetType.ENDPOINT, AssetType.JS_URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL, AssetType.LIVE_HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = [
            "katana",
            "-u",
            url,
            "-json",
            "-silent",
            "-depth",
            str(_DEPTH[scan_input.mode]),
        ]
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-js-crawl", "-known-files", "all", "-automatic-form-fill"]
        if scan_input.rate_limit is not None:
            cmd += ["-rate-limit", str(scan_input.rate_limit)]
        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
        if scan_input.proxy:
            cmd += ["-proxy", scan_input.proxy]
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

            endpoint = item.get("request", {}).get("endpoint") or item.get("endpoint", "")
            method = item.get("request", {}).get("method", "GET")
            source = item.get("source", "")
            if not endpoint:
                continue

            findings.append(
                Finding(
                    title=f"Endpoint: {method} {endpoint}",
                    severity=Severity.INFO,
                    description=f"Crawled endpoint: {method} {endpoint}" + (f" (source: {source})" if source else ""),
                    tool=self.name,
                    target=target,
                    raw=item,
                )
            )
        return findings

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        assets = []
        for f in result.findings:
            endpoint = f.raw.get("request", {}).get("endpoint") or f.raw.get("endpoint", "")
            if not endpoint:
                continue
            if endpoint.endswith(".js"):
                atype = AssetType.JS_URL
            elif f.raw.get("request", {}).get("method", "GET") != "GET":
                atype = AssetType.ENDPOINT
            else:
                atype = AssetType.URL
            assets.append(Asset(type=atype, value=endpoint, source=self.name, target=result.target))
        return assets
