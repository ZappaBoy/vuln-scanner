import os
import shutil
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
)


class ParamSpiderTool(AbstractTool):
    name: str = "paramspider"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # Not used — run() is overridden to handle paramspider's fixed output path
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)

            has_params = "?" in url and "=" in url
            findings.append(Finding(
                title=f"Parameterised URL: {url[:120]}",
                severity=Severity.INFO,
                description=f"URL with parameters discovered from web archives: {url}",
                tool=self.name,
                target=target,
                raw={"url": url, "has_params": has_params},
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        workdir = tempfile.mkdtemp(prefix="vs_paramspider_")
        start = time.monotonic()

        try:
            cmd = ["paramspider", "-d", domain]
            if scan_input.mode == ScanMode.AGGRESSIVE:
                cmd += ["--subs"]
            cmd += scan_input.extra_args

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=workdir, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start

            # paramspider v2 writes to output/<domain>.txt relative to cwd
            output_file = os.path.join(workdir, "output", f"{domain}.txt")
            raw = ""
            if os.path.isfile(output_file):
                with open(output_file, encoding="utf-8", errors="replace") as f:
                    raw = f.read()
            else:
                raw = proc.stdout

            findings = self.parse_output(raw, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=proc.stdout + proc.stderr,
            )

        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout),
                              status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target,
                              status=ScanStatus.FAILED,
                              error="Binary not found: paramspider")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
