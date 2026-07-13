import logging
import subprocess
import time
from abc import ABC, abstractmethod
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)


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
    targets: list[str]
    timeout: int = 300
    mode: ScanMode = ScanMode.PASSIVE
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
        """Return the subprocess argv list for the given target."""

    @abstractmethod
    def parse_output(self, raw: str, target: str) -> list[Finding]:
        """Parse raw tool stdout into a list of Finding objects."""

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        cmd = self.build_command(target, scan_input)
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
            raw = proc.stdout + proc.stderr

            if proc.returncode != 0:
                log.warning("[%s] Exited with code %d on target %s.", self.name, proc.returncode, target)
                return ScanResult(
                    tool=self.name,
                    target=target,
                    duration=duration,
                    status=ScanStatus.FAILED,
                    error=f"Exit code {proc.returncode}: {proc.stderr.strip()}",
                    raw_output=raw,
                )

            findings = self.parse_output(proc.stdout, target)
            log.debug("[%s] %d finding(s) on %s.", self.name, len(findings), target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=raw,
            )

        except subprocess.TimeoutExpired:
            log.warning("[%s] Timed out after %ds on target %s.", self.name, scan_input.timeout, target)
            return ScanResult(
                tool=self.name,
                target=target,
                duration=scan_input.timeout,
                status=ScanStatus.TIMEOUT,
                error=f"Tool timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            log.error("[%s] Binary not found: %r. Is it installed?", self.name, cmd[0])
            return ScanResult(
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.FAILED,
                error=f"Tool binary not found: {cmd[0]!r}. Is it installed?",
            )
