"""WhatWaf — detect and bypass web application firewalls."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_WAF_RE = re.compile(r"(?:detected|identified)[:\s]+([^\n]+WAF[^\n]*)", re.IGNORECASE)
_BYPASS_RE = re.compile(r"(?:bypass|tamper)[:\s]+([^\n]+)", re.IGNORECASE)
_PROTECTED_RE = re.compile(r"(?:protected by|behind)[:\s]+([^\n]+)", re.IGNORECASE)


class WhatWafTool(AbstractTool):
    name: str = "whatwaf"
    binary: str = "whatwaf"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        return ["whatwaf", "-u", url, "--ra", "--timeout", "10", "--no-color"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        waf_name = ""
        for line in raw.splitlines():
            m = _WAF_RE.search(line) or _PROTECTED_RE.search(line)
            if m and not waf_name:
                waf_name = m.group(1).strip()
                findings.append(
                    Finding(
                        title=f"WAF detected: {waf_name}",
                        severity=Severity.INFO,
                        description=f"WhatWaf detected a Web Application Firewall on {target}: {waf_name}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"waf": waf_name},
                    )
                )
            bm = _BYPASS_RE.search(line)
            if bm:
                bypass = bm.group(1).strip()
                findings.append(
                    Finding(
                        title=f"WAF bypass technique: {bypass[:60]}",
                        severity=Severity.MEDIUM,
                        description=f"WhatWaf found a potential bypass for the WAF on {target}: {bypass}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-693"],
                        raw={"bypass": bypass},
                    )
                )
        return findings
