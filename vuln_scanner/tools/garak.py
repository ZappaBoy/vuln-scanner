"""Garak — LLM security probe (tests for jailbreaks, prompt injection, etc.)."""
import json
import re
import subprocess
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, _as_url

_FAILURE_RE = re.compile(r"FAIL(?:ED)?[:\s]+(.+)", re.IGNORECASE)
_PROBE_RE = re.compile(r"probe[:\s]+(.+?)\s+(?:failed|pass|score)", re.IGNORECASE)


class GarakTool(AbstractTool):
    name: str = "garak"
    binary: str = "garak"
    category: str = "llm"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        # garak can probe a REST endpoint; aggressive mode runs more probes
        probes = (
            "all" if scan_input.mode == ScanMode.AGGRESSIVE
            else "knownbadsignatures,promptinject,jailbreak"
        )
        return [
            "python3", "-m", "garak",
            "--model_type", "rest",
            "--model_name", url,
            "--probes", probes,
            "--format", "json",
        ]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if obj.get("outcome") == "FAIL":
                    probe = obj.get("probe", "")
                    detector = obj.get("detector", "")
                    findings.append(Finding(
                        title=f"Garak LLM failure: {probe}/{detector}",
                        severity=Severity.HIGH,
                        description=(
                            f"LLM security probe failed: {probe}\nDetector: {detector}\n"
                            f"The model may be vulnerable to this attack class."
                        ),
                        tool=self.name,
                        target=target,
                        cwe=["CWE-1039"],
                        raw=obj,
                    ))
            except json.JSONDecodeError:
                m = _FAILURE_RE.search(line)
                if m:
                    findings.append(Finding(
                        title=f"Garak: {m.group(1).strip()[:80]}",
                        severity=Severity.MEDIUM,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-1039"],
                        raw={"line": line},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        url = _as_url(target)
        start = time.monotonic()
        try:
            probes = (
                "all" if scan_input.mode == ScanMode.AGGRESSIVE
                else "knownbadsignatures,promptinject,jailbreak"
            )
            proc = subprocess.run(
                ["python3", "-m", "garak",
                 "--model_type", "rest",
                 "--model_name", url,
                 "--probes", probes,
                 "--report_prefix", "/tmp/garak_report"],
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
                              status=ScanStatus.FAILED, error="garak not installed (pip install garak)")
