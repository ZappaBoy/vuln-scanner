"""Progress-bar tracker: stays active across chained waves; dedupes tool names.

Regression for the chaining progress-bar bug where finishing Wave 0 (done ==
total) permanently deactivated the tracker, so later waves concatenated the bar
onto log lines.
"""

import vuln_scanner.progress as orch
from vuln_scanner.tools.enums import ScanStatus


def _tty_tracker(total: int) -> orch.ProgressTracker:
    t = orch.ProgressTracker(total)
    t._tty = True  # force the TTY render path (pytest stderr is not a tty)
    orch._active_tracker = t
    return t


def test_tracker_stays_active_when_done_equals_total():
    t = _tty_tracker(2)
    try:
        t.start("toolA→x")
        t.start("toolB→y")
        t.finish("toolA→x", ScanStatus.SUCCESS)
        t.finish("toolB→y", ScanStatus.SUCCESS)  # done == total == 2 (end of wave 0)
        # Must NOT deactivate mid-scan — later waves still need the bar cleared
        # around log lines by ProgressAwareHandler.
        assert orch._active_tracker is t
    finally:
        orch._active_tracker = None


def test_tracker_survives_next_wave_add_total():
    t = _tty_tracker(2)
    try:
        t.finish("a→x", ScanStatus.SUCCESS)
        t.finish("b→y", ScanStatus.SUCCESS)  # done == total
        t.add_total(3)  # wave 1 adds tasks
        assert orch._active_tracker is t
        t.finish("c→z", ScanStatus.SUCCESS)
        assert orch._active_tracker is t
    finally:
        orch._active_tracker = None


def test_close_deactivates():
    t = _tty_tracker(1)
    try:
        t.finish("a→x", ScanStatus.SUCCESS)
        assert orch._active_tracker is t
        t.close()
        assert orch._active_tracker is None
    finally:
        orch._active_tracker = None


def test_close_is_safe_without_render():
    # No tasks finished → nothing rendered → close() must not print a stray line.
    t = _tty_tracker(0)
    try:
        t.close()
        assert orch._active_tracker is None
    finally:
        orch._active_tracker = None


def test_running_list_dedupes_tool_names(capsys):
    t = orch.ProgressTracker(10)
    t._tty = True
    for i in range(5):
        t.start(f"apifuzzer→t{i}")
    t.start("nikto→a")
    with t._lock:
        t._render_tty()
    err = capsys.readouterr().err
    # Distinct tool names only — no "apifuzzer, apifuzzer, apifuzzer …"
    assert err.count("apifuzzer") == 1
    assert "nikto" in err


def test_render_clears_to_end_of_line(capsys):
    t = orch.ProgressTracker(4)
    t._tty = True
    t.start("toolA→x")
    with t._lock:
        t._render_tty()
    err = capsys.readouterr().err
    # ANSI clear-to-EOL guards against leftover chars when the line shrinks.
    assert "\033[2K" in err


# ── Generic phase / advance (LLM / PoC reuse) ────────────────────────────────


def test_phase_label_in_bar(capsys):
    t = orch.ProgressTracker(3, phase="LLM triage")
    t._tty = True
    t.advance(ScanStatus.SUCCESS)
    err = capsys.readouterr().err
    assert "LLM triage" in err
    assert "1/3" in err
    t.close()


def test_advance_tallies_ok_fail_skip():
    t = orch.ProgressTracker(3)
    t._tty = True
    try:
        t.advance(ScanStatus.SUCCESS)
        t.advance(ScanStatus.FAILED)
        t.advance(ScanStatus.SKIPPED)
        assert (t._ok, t._fail, t._skip, t._done) == (1, 1, 1, 3)
    finally:
        orch._active_tracker = None


def test_summary_line_includes_phase():
    t = orch.ProgressTracker(2, phase="PoC gen")
    t._tty = False
    t.advance(ScanStatus.SUCCESS)
    assert t.summary_line().startswith("PoC gen: ")
