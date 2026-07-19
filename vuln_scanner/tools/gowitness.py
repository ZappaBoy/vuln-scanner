"""gowitness — headless screenshot capture for web asset discovery.

Captures a screenshot of each URL and emits an INFO finding with the
screenshot path so it appears in the report assets section.
"""
import os
import subprocess
import time
from pathlib import Path

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url


# Default screenshot directory — overridden per-run by main.py via configure().
_SCREENSHOT_DIR = Path(os.environ.get("VS_SCREENSHOT_DIR", "./reports/screenshots"))


def configure(screenshot_dir: Path) -> None:
    """Set the screenshot output directory for the current run."""
    global _SCREENSHOT_DIR
    _SCREENSHOT_DIR = screenshot_dir


class GowitnesssTool(AbstractTool):
    name: str = "gowitness"
    category: str = "recon"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        cmd = [
            "gowitness", "single",
            "--url", url,
            "--screenshot-path", str(_SCREENSHOT_DIR),
            "--timeout", str(min(30, scan_input.timeout)),
            "--disable-db",
        ]
        if scan_input.proxy:
            cmd += ["--proxy", scan_input.proxy]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        # gowitness doesn't produce structured findings — look for the written file
        url = _as_url(target)
        # gowitness names screenshots by URL hash; search for any recent png
        screenshots = sorted(_SCREENSHOT_DIR.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not screenshots:
            return []
        latest = screenshots[0]
        return [Finding(
            title=f"Screenshot captured: {url}",
            severity=Severity.INFO,
            description=f"Web screenshot saved to: {latest}",
            tool=self.name,
            target=target,
            raw={"screenshot_path": str(latest), "url": url},
        )]

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=scan_input.timeout
            )
            duration = time.monotonic() - start
            findings = self.parse_output(proc.stdout + proc.stderr, target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc.stdout + proc.stderr,
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error="Binary not found: gowitness",
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name, target=target,
                duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                error=f"gowitness timed out after {scan_input.timeout}s",
            )
