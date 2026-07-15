import logging
import os
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)

OUTPUT_FILE_SENTINEL = "__OUTPUT_FILE__"


def _as_url(target: str, scheme: str = "http") -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"


def _parse_severity(s: str) -> "Severity":
    s = s.lower().strip()
    if s in ("critical", "c"):
        return Severity.CRITICAL
    if s in ("high", "h"):
        return Severity.HIGH
    if s in ("medium", "m", "warning", "warn", "moderate", "3"):
        return Severity.MEDIUM
    if s in ("low", "l", "1"):
        return Severity.LOW
    return Severity.INFO


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


class ScanStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class ScanMode(str, Enum):
    PARANOID = "paranoid"
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    tool: str
    target: str
    cve: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class ScanInput(BaseModel):
    # Each entry may be any of:
    #   hostname / IP / CIDR   → network tools (nmap, masscan, …)
    #   URL                    → web tools (nikto, zap, sslyze, …)
    #   absolute file path     → SAST / secret / SCA tools (semgrep, bandit, gitleaks, …)
    #   absolute directory     → SAST / IaC / SCA tools (checkov, tfsec, trivy fs, …)
    #   container image ref    → container tools (trivy image, grype, …)
    # Tools silently skip targets that are not relevant to their scan type.
    targets: list[str]
    timeout: int = 300
    mode: ScanMode = ScanMode.PASSIVE
    rate_limit: int | None = None  # requests per second; None = no limit
    extra_args: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    tool: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    duration: float = 0.0
    status: ScanStatus = ScanStatus.SUCCESS
    error: str | None = None
    raw_output: str = ""


class AbstractTool(ABC, BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    category: str

    @abstractmethod
    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        """Return the subprocess argv list for the given target.
        Use OUTPUT_FILE_SENTINEL where the output file path should go."""

    @abstractmethod
    def parse_output(self, raw: str, target: str) -> list[Finding]:
        """Parse raw tool output (stdout or file content) into Finding objects."""

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        """Execute against target using stdout capture."""
        cmd = self.build_command(target, scan_input)
        return self._exec(cmd, target, scan_input, raw_from="stdout")

    def _run_with_tempfile(
        self, target: str, scan_input: ScanInput, suffix: str = ".json"
    ) -> ScanResult:
        """Execute against target; tool writes results to a temp file.

        build_command() must include OUTPUT_FILE_SENTINEL where the path goes.
        """
        fd, tmpfile = tempfile.mkstemp(suffix=suffix, prefix=f"vs_{self.name}_")
        os.close(fd)
        try:
            cmd = [
                tmpfile if arg == OUTPUT_FILE_SENTINEL else arg
                for arg in self.build_command(target, scan_input)
            ]
            return self._exec(cmd, target, scan_input, raw_from="file", output_file=tmpfile)
        finally:
            try:
                os.unlink(tmpfile)
            except FileNotFoundError:
                pass

    def _exec(
        self,
        cmd: list[str],
        target: str,
        scan_input: ScanInput,
        raw_from: str = "stdout",
        output_file: str | None = None,
    ) -> ScanResult:
        log.debug("[%s] Running: %s", self.name, " ".join(cmd))
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            proc_output = proc.stdout + proc.stderr

            if raw_from == "file" and output_file:
                try:
                    raw = Path(output_file).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    raw = ""
            else:
                raw = proc.stdout

            # Some tools exit non-zero even on success (e.g. found vulns); let parse decide
            if proc.returncode not in (0, 1) and not raw.strip():
                log.warning("[%s] Exited %d on %s.", self.name, proc.returncode, target)
                return ScanResult(
                    tool=self.name,
                    target=target,
                    duration=duration,
                    status=ScanStatus.FAILED,
                    error=f"Exit code {proc.returncode}: {proc.stderr.strip()[:200]}",
                    raw_output=proc_output,
                )

            findings = self.parse_output(raw, target)
            log.debug("[%s] %d finding(s) on %s.", self.name, len(findings), target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc_output,
            )

        except subprocess.TimeoutExpired:
            log.warning("[%s] Timed out after %ds on %s.", self.name, scan_input.timeout, target)
            return ScanResult(
                tool=self.name,
                target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Tool timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            log.debug("[%s] Binary not found: %r — skipping.", self.name, cmd[0])
            return ScanResult(
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.SKIPPED,
            )
