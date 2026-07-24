"""tplmap — Server-Side Template Injection (SSTI) detection and exploitation."""

import re

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

# "[+] Jinja2 plugin is testing..."
# "[+] https://target.com/?name=* is vulnerable to SSTI with engine Jinja2"
_VULN_RE = re.compile(
    r"\[\+\].*?(?P<url>https?://\S+)\s+is\s+vulnerable.*?engine\s+(?P<engine>\w+)",
    re.IGNORECASE,
)
_ENGINE_RE = re.compile(r"\[\+\].*engine[:\s]+(?P<engine>\w[\w\+\.]+)", re.IGNORECASE)
_INJECT_RE = re.compile(r"Tplmap identified the following injection", re.IGNORECASE)


class TplmapTool(AbstractTool):
    name: str = "tplmap"
    binary: str = "tplmap"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = ["tplmap", "-u", url]

        if scan_input.mode == ScanMode.PARANOID:
            cmd += ["--level", "1"]
        elif scan_input.mode == ScanMode.ACTIVE:
            cmd += ["--level", "3"]
        elif scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["--level", "5", "--os-cmd", "id"]

        auth = scan_input.auth
        if auth.is_configured:
            for k, v in auth.effective_headers.items():
                cmd += ["-H", f"{k}: {v}"]
            if auth.cookie_string:
                cmd += ["--cookie", auth.cookie_string]

        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Look for confirmed injection
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                url = m.group("url")
                engine = m.group("engine")
                findings.append(
                    Finding(
                        title=f"SSTI via {engine} template engine at {url}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Server-Side Template Injection detected at {url}.\n"
                            f"Template engine: {engine}\n"
                            f"SSTI can lead to Remote Code Execution (RCE)."
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-94"],
                        raw={"url": url, "engine": engine, "line": line},
                    )
                )
                continue

            # Fallback: generic injection banner
            if _INJECT_RE.search(line):
                eng_m = _ENGINE_RE.search(raw)
                engine = eng_m.group("engine") if eng_m else "unknown"
                findings.append(
                    Finding(
                        title=f"SSTI detected at {target} (engine: {engine})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Tplmap identified a Server-Side Template Injection vulnerability at {target}.\n"
                            f"Template engine: {engine}\n"
                            f"SSTI can lead to Remote Code Execution (RCE)."
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-94"],
                        raw={"engine": engine},
                    )
                )
                break

        return findings
