"""AbstractTool ABC and subprocess execution helpers."""
import logging
import os
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vuln_scanner.tools.enums import ScanStatus, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.target import _ALL_TARGET_TYPES, classify_target

log = logging.getLogger(__name__)

_RAW_TRUNCATE = 8192  # chars logged per stream in DEBUG mode
_STORED_RAW_MAX = 4096  # chars kept in ScanResult.raw_output; full output is in scan.log


def _log_tool_output(logger: logging.Logger, name: str, stdout: str, stderr: str) -> None:
    """Emit tool stdout/stderr at DEBUG level, truncated to avoid log spam."""
    for stream, label in ((stdout, "stdout"), (stderr, "stderr")):
        stripped = stream.strip()
        if not stripped:
            continue
        if len(stripped) > _RAW_TRUNCATE:
            stripped = stripped[:_RAW_TRUNCATE] + f"\n… [{len(stream) - _RAW_TRUNCATE} chars truncated]"
        logger.debug("[%s] %s:\n%s", name, label, stripped)

# Place in a command list where the output file path should be substituted.
OUTPUT_FILE_SENTINEL = "__OUTPUT_FILE__"


def _as_url(target: str, scheme: str = "http") -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"


class AbstractTool(ABC, BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    # The name of the executable that cmd[0] resolves to (used for binary-presence
    # checks and error messages). Empty string for API-only tools with no local binary.
    binary: str = ""
    category: str

    # Override in subclasses to restrict which target types this tool handles.
    # Default = all types so tools without an override keep working.
    applicable_targets: frozenset[TargetType] = _ALL_TARGET_TYPES

    # Flags appended to the command when the root logger is at DEBUG level.
    verbose_flags: list[str] = []
    # Flags stripped from the command when the root logger is at DEBUG level
    # (e.g. remove "--quiet" / "--silent" so full tool output is visible).
    silent_flags: list[str] = []

    def applies_to(self, target: str) -> bool:
        """Return True if this tool should run against *target*."""
        if self.applicable_targets is _ALL_TARGET_TYPES:
            return True
        return bool(classify_target(target) & self.applicable_targets)

    @abstractmethod
    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        """Return the subprocess argv list for *target*.

        Use OUTPUT_FILE_SENTINEL where the output file path should go.
        """

    @abstractmethod
    def parse_output(self, raw: str, target: str) -> list[Finding]:
        """Parse raw tool output into Finding objects."""

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        """Execute against *target*, capturing stdout."""
        cmd = self.build_command(target, scan_input)
        return self._exec(cmd, target, scan_input, raw_from="stdout")

    def _run_with_tempfile(
        self, target: str, scan_input: ScanInput, suffix: str = ".json"
    ) -> ScanResult:
        """Execute against *target*; tool writes results to a temp file."""
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
        debug = log.isEnabledFor(logging.DEBUG)
        if debug and (self.silent_flags or self.verbose_flags):
            cmd = [a for a in cmd if a not in self.silent_flags]
            cmd = cmd + self.verbose_flags

        log.debug("[%s] cmd: %s", self.name, " ".join(cmd))
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start
            proc_output = (proc.stdout + proc.stderr)[:_STORED_RAW_MAX]

            if debug:
                _log_tool_output(log, self.name, proc.stdout, proc.stderr)

            if raw_from == "file" and output_file:
                try:
                    raw = Path(output_file).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    raw = ""
            else:
                raw = proc.stdout

            if proc.returncode not in (0, 1) and not raw.strip():
                log.warning("[%s] exited %d on %s", self.name, proc.returncode, target)
                return ScanResult(
                    tool=self.name,
                    target=target,
                    duration=duration,
                    status=ScanStatus.FAILED,
                    error=f"Exit code {proc.returncode}: {proc.stderr.strip()[:200]}",
                    raw_output=proc_output,
                )

            findings = self.parse_output(raw, target)
            log.debug("[%s] %d finding(s) on %s", self.name, len(findings), target)
            return ScanResult(
                tool=self.name,
                target=target,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc_output,
            )

        except subprocess.TimeoutExpired:
            log.warning("[%s] timed out after %ds on %s", self.name, scan_input.timeout, target)
            return ScanResult(
                tool=self.name,
                target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Tool timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            binary_name = self.binary or (cmd[0] if cmd else self.name)
            log.error("[%s] binary not found: %r — tool must be installed in the image", self.name, binary_name)
            return ScanResult(
                tool=self.name,
                target=target,
                duration=0.0,
                status=ScanStatus.FAILED,
                error=f"Binary not found: {binary_name}",
            )
