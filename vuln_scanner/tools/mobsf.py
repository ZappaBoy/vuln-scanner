"""MobSF — Mobile Security Framework static analysis via REST API."""
import json
import os
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_SEV_MAP = {"high": Severity.HIGH, "warning": Severity.MEDIUM,
            "info": Severity.INFO, "secure": Severity.INFO, "hotspot": Severity.LOW}

_MOBSF_URL = os.environ.get("VS_MOBSF_URL", "http://localhost:8000")
_MOBSF_KEY = os.environ.get("VS_MOBSF_API_KEY", "")


class MobSFTool(AbstractTool):
    name: str = "mobsf"
    category: str = "mobile"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.PATH})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for check_name, check_data in data.get("android_api", {}).items():
                status = check_data.get("level", "info").lower()
                sev = _SEV_MAP.get(status, Severity.INFO)
                if sev == Severity.INFO:
                    continue
                desc = check_data.get("description", "")
                findings.append(Finding(
                    title=f"MobSF [{check_name}]: {desc[:80]}",
                    severity=sev,
                    description=desc,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=check_data,
                ))
            # Code analysis findings
            for issue in data.get("code_analysis", {}).get("findings", {}).values():
                status = issue.get("level", "info").lower()
                sev = _SEV_MAP.get(status, Severity.INFO)
                title = issue.get("title", "")
                desc = issue.get("description", "")
                findings.append(Finding(
                    title=f"MobSF code [{title[:60]}]",
                    severity=sev,
                    description=desc or title,
                    tool=self.name,
                    target=target,
                    cwe=[],
                    raw=issue,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        if not _MOBSF_KEY:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED,
                              error="MobSF API key not set (VS_MOBSF_API_KEY)")
        start = time.monotonic()
        try:
            import urllib.request
            import urllib.parse
            # Upload APK/IPA
            with open(target, "rb") as f:
                data = f.read()
            fname = os.path.basename(target)
            boundary = "boundary123456"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(
                f"{_MOBSF_URL}/api/v1/upload",
                data=body,
                headers={"Authorization": _MOBSF_KEY,
                         "Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                upload_data = json.loads(resp.read())
            file_hash = upload_data.get("hash", "")
            # Scan
            scan_body = urllib.parse.urlencode({"hash": file_hash, "re_scan": "0"}).encode()
            req2 = urllib.request.Request(
                f"{_MOBSF_URL}/api/v1/scan",
                data=scan_body,
                headers={"Authorization": _MOBSF_KEY,
                         "Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req2, timeout=scan_input.timeout) as resp2:
                scan_result = json.loads(resp2.read())
            duration = time.monotonic() - start
            raw = json.dumps(scan_result)
            return ScanResult(
                tool=self.name, target=target,
                findings=self.parse_output(raw, target),
                duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
            )
        except Exception as e:
            return ScanResult(tool=self.name, target=target,
                              duration=time.monotonic() - start,
                              status=ScanStatus.FAILED, error=str(e))
