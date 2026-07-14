import json
import os
import subprocess
import tempfile
import time

from vuln_scanner.tools.base import (
    AbstractTool,
    Finding,
    ScanInput,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    _as_url,
    _parse_severity,
)

_CHECKS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID: ["--checks=xss*,sqli*", "--audit-links", "--audit-forms"],
    ScanMode.PASSIVE:  ["--checks=xss*,sqli*", "--audit-links", "--audit-forms"],
    ScanMode.ACTIVE:   ["--checks=*", "--audit-links", "--audit-forms", "--audit-cookies", "--audit-headers"],
    ScanMode.AGGRESSIVE: ["--checks=*", "--audit-links", "--audit-forms",
                          "--audit-cookies", "--audit-headers", "--audit-jsons",
                          "--audit-xmls", "--audit-ui-forms"],
}


class ArachniTool(AbstractTool):
    name: str = "arachni"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # two-step execution handled in run()

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for issue in data.get("issues", []):
            sev_label = issue.get("severity", "info")
            severity = _parse_severity(sev_label)
            url = issue.get("vector", {}).get("url", target)
            findings.append(Finding(
                title=issue.get("name", "Arachni finding"),
                severity=severity,
                description=(
                    issue.get("description", "")
                    + f"\nURL: {url}"
                    + f"\nInput: {issue.get('vector', {}).get('input', '')}"
                ),
                tool=self.name,
                target=url or target,
                references=issue.get("references", {}).get("url", []),
                cve=[c for c in issue.get("references", {}).get("cve", [])
                     if c.startswith("CVE-")],
                raw=issue,
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        import logging
        log = logging.getLogger(__name__)
        start = time.monotonic()

        fd_afr, afr_path = tempfile.mkstemp(suffix=".afr", prefix="vs_arachni_")
        os.close(fd_afr)
        fd_json, json_path = tempfile.mkstemp(suffix=".json", prefix="vs_arachni_report_")
        os.close(fd_json)

        try:
            # Step 1: scan → .afr
            checks = _CHECKS.get(scan_input.mode, _CHECKS[ScanMode.ACTIVE])
            scan_cmd = [
                "arachni",
                _as_url(target),
                f"--save-afr={afr_path}",
                "--output-only-positives",
            ] + checks + scan_input.extra_args

            log.debug("[arachni] Running: %s", " ".join(scan_cmd))
            try:
                subprocess.run(
                    scan_cmd, capture_output=True, text=True,
                    timeout=scan_input.timeout,
                )
            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout),
                    status=ScanStatus.TIMEOUT,
                    error=f"Timed out after {scan_input.timeout}s",
                )
            except FileNotFoundError:
                return ScanResult(
                    tool=self.name, target=target, duration=0.0,
                    status=ScanStatus.FAILED, error="arachni binary not found.",
                )

            # Step 2: convert .afr → JSON report
            report_cmd = [
                "arachni_reporter", afr_path,
                f"--reporter=json:outfile={json_path}",
            ]
            log.debug("[arachni] Converting report: %s", " ".join(report_cmd))
            try:
                subprocess.run(report_cmd, capture_output=True, text=True, timeout=60)
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=time.monotonic() - start,
                    status=ScanStatus.FAILED,
                    error=f"arachni_reporter failed: {exc}",
                )

            raw = ""
            if os.path.exists(json_path):
                raw = open(json_path).read()

            findings = self.parse_output(raw, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=time.monotonic() - start, status=ScanStatus.SUCCESS,
            )

        finally:
            for p in (afr_path, json_path):
                if os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
