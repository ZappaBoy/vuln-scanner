import json
import logging
import subprocess
import time
import urllib.request

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

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
    binary: str = "jsluice"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST, TargetType.IP})

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

    # Common web ports to probe when the target has no explicit port.
    _WEB_PORTS = [80, 8080, 3000, 8000, 8888, 8443, 443]

    def _candidate_urls(self, target: str) -> list[str]:
        """Return ordered list of URLs to try fetching JS from."""
        if target.startswith(("http://", "https://")):
            return [target]
        # Plain hostname or IP — probe common ports, http before https.
        urls = []
        for port in self._WEB_PORTS:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{target}:{port}")
        return urls

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()

        urls_to_try = self._candidate_urls(target)
        content = None
        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "vuln-scanner/jsluice"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    content = resp.read()
                break
            except Exception:
                continue

        if content is None:
            # Can't reach the target on any common port — not a tool error.
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.SKIPPED,
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
                              status=ScanStatus.SKIPPED)
