"""
Acunetix REST API integration (commercial tool).
Requires VS_ACUNETIX_URL and VS_ACUNETIX_API_KEY environment variables.
"""
import os
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_PROFILE_IDS: dict[ScanMode, str] = {
    ScanMode.PARANOID: "11111111-1111-1111-1111-111111111115",   # Passive scan
    ScanMode.PASSIVE:  "11111111-1111-1111-1111-111111111115",   # Passive scan
    ScanMode.ACTIVE:   "11111111-1111-1111-1111-111111111112",   # High Risk Vulnerabilities
    ScanMode.AGGRESSIVE: "11111111-1111-1111-1111-111111111111", # Full scan
}


class AcunetixTool(AbstractTool):
    name: str = "acunetix"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # API-based; subprocess not used

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []  # parsing done inline in run()

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        import logging
        log = logging.getLogger(__name__)
        start = time.monotonic()

        api_url = os.environ.get("VS_ACUNETIX_URL", "").rstrip("/")
        api_key = os.environ.get("VS_ACUNETIX_API_KEY", "")
        if not api_url or not api_key:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.SKIPPED,
                error="VS_ACUNETIX_URL and VS_ACUNETIX_API_KEY must be set.",
            )
        if not _HAS_REQUESTS:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error="requests library not available.",
            )

        session = _requests.Session()
        session.headers.update({"X-Auth": api_key, "Content-Type": "application/json"})
        session.verify = False  # Acunetix often uses self-signed cert

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        try:
            # 1. Add target
            r = session.post(f"{api_url}/api/v1/targets",
                             json={"address": url, "description": "vuln-scanner", "type": "default"},
                             timeout=30)
            r.raise_for_status()
            target_id = r.json()["target_id"]

            # 2. Start scan
            profile_id = _PROFILE_IDS.get(scan_input.mode, _PROFILE_IDS[ScanMode.ACTIVE])
            r = session.post(f"{api_url}/api/v1/scans",
                             json={"target_id": target_id, "profile_id": profile_id,
                                   "schedule": {"disable": False, "start_date": None, "time_sensitive": False}},
                             timeout=30)
            r.raise_for_status()
            scan_id = r.json()["scan_id"]
            log.info("[acunetix] Scan %s started for %s", scan_id, target)

            # 3. Poll for completion
            deadline = time.monotonic() + scan_input.timeout
            while time.monotonic() < deadline:
                r = session.get(f"{api_url}/api/v1/scans/{scan_id}", timeout=30)
                r.raise_for_status()
                status = r.json().get("current_session", {}).get("status", "")
                if status in ("completed", "failed", "aborted"):
                    break
                time.sleep(15)

            # 4. Fetch vulnerabilities
            r = session.get(f"{api_url}/api/v1/vulnerabilities",
                            params={"q": f"scan.{scan_id}", "l": 500}, timeout=30)
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])

            findings: list[Finding] = []
            for v in vulns:
                sev_label = v.get("severity", "info")
                sev = _parse_severity(sev_label)
                findings.append(Finding(
                    title=v.get("vt_name", "Unknown vulnerability"),
                    severity=sev,
                    description=v.get("affects_url", target),
                    tool=self.name,
                    target=target,
                    cve=[c for c in v.get("cvss_score", {}) if str(c).startswith("CVE-")],
                    raw=v,
                ))

            # 5. Cleanup: delete scan + target
            session.delete(f"{api_url}/api/v1/scans/{scan_id}", timeout=30)
            session.delete(f"{api_url}/api/v1/targets/{target_id}", timeout=30)

            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=time.monotonic() - start, status=ScanStatus.SUCCESS,
            )

        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                tool=self.name, target=target,
                duration=time.monotonic() - start,
                status=ScanStatus.FAILED, error=str(exc),
            )
