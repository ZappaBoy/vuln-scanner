"""Promptmap — automated prompt injection testing for LLM apps."""
import json
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_INJECT_RE = re.compile(r"(?:injection|jailbreak|bypass|success)[:\s]+(.+)", re.IGNORECASE)
_FAIL_RE = re.compile(r"VULNERABLE[:\s]+(.+)", re.IGNORECASE)


class PromptmapTool(AbstractTool):
    name: str = "promptmap"
    category: str = "llm"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        mode = "extensive" if scan_input.mode == ScanMode.AGGRESSIVE else "normal"
        cmd = [
            "python3", "/opt/promptmap/promptmap.py",
            "--endpoint", url,
            "--mode", mode,
        ]
        if scan_input.auth.bearer_token:
            cmd += ["--api-key", scan_input.auth.bearer_token]
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            for result in data.get("results", []):
                if result.get("status") == "vulnerable":
                    attack = result.get("attack_type", "prompt injection")
                    desc = result.get("description", "")
                    findings.append(Finding(
                        title=f"Prompt injection: {attack}",
                        severity=Severity.HIGH,
                        description=f"promptmap detected successful {attack}:\n{desc}",
                        tool=self.name,
                        target=target,
                        cwe=["CWE-1039"],
                        raw=result,
                    ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                m = _FAIL_RE.search(line) or _INJECT_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"Prompt injection: {m.group(1).strip()[:80]}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-1039"],
                        raw={"line": line},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                self.build_command(target, scan_input),
                capture_output=True, text=True, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            return ScanResult(
                tool=self.name, target=target,
                findings=self.parse_output(raw, target),
                duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED, error="promptmap not found at /opt/promptmap")
