"""git-dumper — detect and dump exposed .git directories from web servers."""
import subprocess
import tempfile
import shutil
import time
import os

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanStatus


class GitDumperTool(AbstractTool):
    name: str = "git-dumper"
    category: str = "secrets"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # built in run() — needs temp dir

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []  # findings built in run() based on exit code / file presence

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        git_url = url.rstrip("/") + "/.git"
        tmpdir = tempfile.mkdtemp(prefix="vs_gitdumper_")
        start = time.monotonic()
        try:
            cmd = ["git-dumper", git_url, tmpdir] + list(scan_input.extra_args)

            if scan_input.auth.is_configured:
                for k, v in scan_input.auth.effective_headers.items():
                    cmd += ["--header", f"{k}: {v}"]

            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=scan_input.timeout,
                )
                duration = time.monotonic() - start
                raw_out = proc.stdout + proc.stderr

                # Successful dump: tmpdir contains .git/ with HEAD file
                dumped = os.path.isfile(os.path.join(tmpdir, ".git", "HEAD"))
                has_objects = os.path.isdir(os.path.join(tmpdir, ".git", "objects"))

                if not dumped:
                    return ScanResult(
                        tool=self.name, target=target, findings=[],
                        duration=duration, status=ScanStatus.SUCCESS,
                        raw_output=raw_out,
                    )

                # Count dumped files
                file_count = sum(
                    1 for _, _, files in os.walk(tmpdir) for _ in files
                )
                description = (
                    f"Exposed .git directory found at {git_url}.\n"
                    f"git-dumper successfully retrieved the repository ({file_count} files).\n"
                    f"Source code, credentials, and history may be fully accessible."
                )
                if has_objects:
                    description += "\n.git/objects/ present — full source code recovery possible."

                finding = Finding(
                    title=f"Exposed .git directory at {url}",
                    severity=Severity.CRITICAL,
                    description=description,
                    tool=self.name,
                    target=target,
                    cwe=["CWE-548", "CWE-312"],
                    raw={"git_url": git_url, "files_dumped": file_count},
                )
                return ScanResult(
                    tool=self.name, target=target, findings=[finding],
                    duration=duration, status=ScanStatus.SUCCESS, raw_output=raw_out,
                )

            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                    error=f"Timed out after {scan_input.timeout}s",
                )
            except FileNotFoundError:
                return ScanResult(
                    tool=self.name, target=target, duration=0.0,
                    status=ScanStatus.FAILED, error="Binary not found: git-dumper",
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
