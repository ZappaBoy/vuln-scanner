import json
import logging
import subprocess
import time
import urllib.request

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
)

log = logging.getLogger(__name__)

_SECRET_SEV: dict[str, Severity] = {
    "AWSAccessKey":    Severity.CRITICAL,
    "AWSSecretKey":    Severity.CRITICAL,
    "PrivateKey":      Severity.CRITICAL,
    "APIKey":          Severity.HIGH,
    "Token":           Severity.HIGH,
    "Password":        Severity.HIGH,
    "Secret":          Severity.HIGH,
    "Credential":      Severity.HIGH,
}


def _secret_severity(kind: str) -> Severity:
    for key, sev in _SECRET_SEV.items():
        if key.lower() in kind.lower():
            return sev
    return Severity.MEDIUM


class JSluiceTool(AbstractTool):
    name: str = "jsluice"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # jsluice reads from stdin; mode determines what we extract
        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            return ["jsluice", "urls", "-"]
        return ["jsluice", "secrets", "-"]

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

            kind = item.get("kind", item.get("type", ""))
            value = item.get("value", item.get("url", ""))
            context = item.get("context", "")
            filename = item.get("filename", target)

            if not value:
                continue

            if kind in ("URL", "url") or value.startswith("http"):
                findings.append(Finding(
                    title=f"URL found in JS: {value[:100]}",
                    severity=Severity.INFO,
                    description=f"URL/endpoint extracted from JavaScript on {filename}: {value}",
                    tool=self.name,
                    target=target,
                    raw=item,
                ))
            else:
                sev = _secret_severity(kind)
                findings.append(Finding(
                    title=f"Potential secret in JS: {kind}",
                    severity=sev,
                    description=(
                        f"Potential secret of type '{kind}' found in JavaScript on {filename}."
                        + (f"\nContext: {context[:200]}" if context else "")
                    ),
                    tool=self.name,
                    target=target,
                    raw=item,
                ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        start = time.monotonic()

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vuln-scanner/jsluice"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
        except Exception as exc:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error=f"Failed to fetch {url}: {exc}",
            )

        cmd = self.build_command(target, scan_input)
        try:
            proc = subprocess.run(
                cmd,
                input=content,
                capture_output=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw_text = proc.stdout.decode("utf-8", errors="replace")
            findings = self.parse_output(raw_text, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=raw_text,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout),
                              status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target,
                              status=ScanStatus.FAILED,
                              error="Binary not found: jsluice")
