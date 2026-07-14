import json
import subprocess
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


class HakrawlerTool(AbstractTool):
    name: str = "hakrawler"
    category: str = "web"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # hakrawler reads the URL from stdin; extra flags passed here
        cmd = ["hakrawler", "-json"]
        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            cmd += ["-subs"]    # include subdomains
        if scan_input.mode == ScanMode.AGGRESSIVE:
            cmd += ["-depth", "3"]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                # plain URL line (non-JSON mode)
                if line.startswith("http"):
                    findings.append(Finding(
                        title=f"URL: {line}",
                        severity=Severity.INFO,
                        description=f"Crawled URL: {line}",
                        tool=self.name,
                        target=target,
                        raw={"url": line},
                    ))
                continue

            url = item.get("url", item.get("href", ""))
            source = item.get("source", "")
            tag = item.get("tag", "")
            if not url:
                continue

            findings.append(Finding(
                title=f"URL: {url}",
                severity=Severity.INFO,
                description=f"Crawled URL: {url}"
                            + (f" (tag: {tag}, source: {source})" if tag or source else ""),
                tool=self.name,
                target=target,
                raw=item,
            ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd = self.build_command(target, scan_input)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=url,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            findings = self.parse_output(proc.stdout, target)
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
                              error="Binary not found: hakrawler")
