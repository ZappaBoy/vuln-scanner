import json
import os
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_VULN_SEVERITY: dict[int, Severity] = {
    3: Severity.HIGH,
    2: Severity.MEDIUM,
    1: Severity.LOW,
    0: Severity.INFO,
}

_PASSIVE_MODULES = "mod_wapp"          # tech detection only
_ACTIVE_MODULES  = "mod_sql,mod_xss,mod_file,mod_exec,mod_blindsql,mod_ssrf,mod_wapp"
_AGGRESSIVE_MODULES = ""               # empty = all modules


class WapitiTool(AbstractTool):
    name: str = "wapiti"
    binary: str = "wapiti"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Not used directly; run() builds command with tmpfile
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for vuln_type, instances in data.get("vulnerabilities", {}).items():
            for item in instances:
                level = item.get("level", 1)
                severity = _VULN_SEVERITY.get(level, Severity.LOW)
                path = item.get("path", item.get("url", target))
                param = item.get("parameter", "")
                desc = item.get("info", vuln_type)
                title = f"{vuln_type}" + (f" via {param}" if param else "")
                findings.append(Finding(
                    title=title[:120],
                    severity=severity,
                    description=f"{desc}\nPath: {path}" + (f"\nParameter: {param}" if param else ""),
                    tool=self.name,
                    target=target,
                    raw=item,
                ))

        for anom_type, instances in data.get("anomalies", {}).items():
            for item in instances:
                findings.append(Finding(
                    title=f"Anomaly: {anom_type}",
                    severity=Severity.LOW,
                    description=item.get("info", anom_type),
                    tool=self.name,
                    target=target,
                    raw=item,
                ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="vs_wapiti_")
        os.close(fd)
        os.unlink(tmpfile)  # wapiti won't overwrite; must not pre-exist

        mode = scan_input.mode
        if mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            modules = _PASSIVE_MODULES
        elif mode == ScanMode.AGGRESSIVE:
            modules = _AGGRESSIVE_MODULES
        else:
            modules = _ACTIVE_MODULES

        cmd = [
            "wapiti",
            "-u", _as_url(target),
            "-f", "json",
            "-o", tmpfile,
            "--flush-session",
            "--max-scan-time", str(scan_input.timeout),
        ]
        if modules:
            cmd += ["-m", modules]
        auth = scan_input.auth
        if auth.is_configured:
            if auth.username and auth.password:
                cmd += ["-a", f"{auth.username}%{auth.password}"]
            if auth.cookie_string:
                cmd += ["--cookie", auth.cookie_string]
            for k, v in auth.headers.items():
                cmd += ["--header", f"{k}: {v}"]
            if auth.bearer_token and "Authorization" not in auth.headers:
                cmd += ["--header", f"Authorization: Bearer {auth.bearer_token}"]
            if auth.login_url:
                cmd += ["--form-cred", auth.login_url]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        cmd += scan_input.extra_args

        import logging
        log = logging.getLogger(__name__)
        log.debug("[%s] Running: %s", self.name, " ".join(cmd))
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=scan_input.timeout + 10
            )
            duration = time.monotonic() - start
            raw = ""
            if os.path.exists(tmpfile):
                raw = open(tmpfile).read()
                os.unlink(tmpfile)
            findings = self.parse_output(raw, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=proc.stdout + proc.stderr,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name, target=target, duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT, error=f"Timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error="wapiti binary not found.",
            )
        finally:
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)
