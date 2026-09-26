"""Reusable TTY progress bar shared by the scan orchestrator and the LLM/PoC/agent phases.

A single ``ProgressTracker`` renders an in-place bar on stderr and cooperates
with ``ProgressAwareHandler`` so log lines never concatenate onto the bar: the
handler clears the bar before each record and the tracker redraws afterwards.

Only one tracker is "active" at a time (the module global ``_active_tracker``);
phases run sequentially, so each phase constructs its own tracker and calls
``close()`` when done.
"""

import logging
import sys
import threading

from vuln_scanner.tools.enums import ScanStatus

# Module-level reference to the active progress tracker so the logging handler
# can clear/redraw the bar line around each log record.
_active_tracker = None


class ProgressTracker:
    """Thread-safe progress counter; renders inline in a TTY, silent otherwise.

    ``phase`` is an optional short label shown in the bar (e.g. ``"LLM triage"``)
    so different pipeline stages are distinguishable.
    """

    def __init__(self, total: int, phase: str = "") -> None:
        global _active_tracker
        self._total = total
        self._done = 0
        self._ok = 0
        self._fail = 0
        self._skip = 0
        self._running: set[str] = set()
        self._phase = phase
        self._lock = threading.Lock()
        self._tty = sys.stderr.isatty()
        self._rendered = False  # True once a bar line has been drawn
        if self._tty:
            _active_tracker = self

    def deactivate(self) -> None:
        global _active_tracker
        if _active_tracker is self:
            _active_tracker = None

    def close(self) -> None:
        """Finalize the bar: terminate the line and stop clearing around logs.

        Called once by the owner when the phase is done.  A tracker must stay
        active across chained waves, so completion is signalled explicitly here
        rather than inferred from ``done == total``.
        """
        with self._lock:
            if self._tty and self._rendered:
                print(file=sys.stderr)
            self.deactivate()

    def add_total(self, n: int) -> None:
        with self._lock:
            self._total += n

    def start(self, label: str) -> None:
        with self._lock:
            self._running.add(label)

    def finish(self, label: str, status: ScanStatus) -> None:
        with self._lock:
            self._running.discard(label)
            self._tally(status)
            if self._tty:
                self._render_tty()

    def advance(self, status: ScanStatus = ScanStatus.SUCCESS) -> None:
        """Increment progress for phases with no start/finish label pairing."""
        with self._lock:
            self._tally(status)
            if self._tty:
                self._render_tty()

    def _tally(self, status: ScanStatus) -> None:
        self._done += 1
        if status == ScanStatus.SUCCESS:
            self._ok += 1
        elif status == ScanStatus.SKIPPED:
            self._skip += 1
        else:
            self._fail += 1

    def _render_tty(self) -> None:
        # Called with _lock held (from finish/advance or from ProgressAwareHandler).
        width = 24
        filled = int(width * self._done / max(self._total, 1))
        bar = "█" * filled + "░" * (width - filled)
        # Show distinct labels only (strip any "→target" suffix and dedupe) so
        # many concurrent same-named tasks don't flood the line.
        names = sorted({label.split("→")[0] for label in self._running})
        display = ", ".join(names[:5])
        if len(names) > 5:
            display += f" +{len(names) - 5}"
        suffix = f"  [{display}]" if display else ""
        prefix = f"{self._phase} " if self._phase else ""
        line = (
            f"\r\033[2K  {prefix}[{bar}] {self._done}/{self._total}  "
            f"✓{self._ok} ✗{self._fail} ~{self._skip}{suffix}"
        )
        print(line, end="", flush=True, file=sys.stderr)
        self._rendered = True

    def summary_line(self) -> str:
        prefix = f"{self._phase}: " if self._phase else ""
        return (
            f"{prefix}{self._total} task(s) completed: "
            f"✓ {self._ok} success  ✗ {self._fail} failed  ~ {self._skip} skipped"
        )


class ProgressAwareHandler(logging.StreamHandler):
    """Logging handler that clears and redraws the TTY progress bar around each record.

    Prevents log lines from being concatenated onto the bar's overwrite line.
    """

    def emit(self, record: logging.LogRecord) -> None:
        tracker = _active_tracker
        if tracker is None or not tracker._tty:
            super().emit(record)
            return
        with tracker._lock:
            # Erase the current bar line, emit the log record, then redraw.
            self.stream.write("\r\033[2K")
            self.stream.flush()
            super().emit(record)
            tracker._render_tty()
