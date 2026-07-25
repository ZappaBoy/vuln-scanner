#!/usr/bin/env python3
"""Invoke every registered tool against fake targets to verify CLI flags.

Each tool is executed with a short timeout against a reserved-address target.
Because real scanning is NOT the goal, a tool *passes* if:
  - Its binary was found (no FileNotFoundError / "Binary not found")
  - Its output does NOT contain flag-parsing error messages

Tools that time out (binary started, ran, hit the timeout) are counted as OK —
the timeout proves the binary launched and accepted the command-line arguments.

Run inside the Docker image:
    docker run --rm <image> uv run python tests/check_invocations.py
    docker run --rm <image> uv run python tests/check_invocations.py --verbose
    docker run --rm <image> uv run python tests/check_invocations.py --tool nmap nuclei

Exit 0  → all invoked tools started without flag errors.
Exit 1  → one or more tools have bad flags, missing binaries, or crashed.
"""

import argparse
import concurrent.futures
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from vuln_scanner.tools import TOOL_REGISTRY
from vuln_scanner.tools.enums import ScanMode, ScanStatus, TargetType
from vuln_scanner.tools.models import ScanInput
from vuln_scanner.tools.target import _ALL_TARGET_TYPES

# ── Fake targets ──────────────────────────────────────────────────────────────
# RFC 5737 (192.0.2.0/24) and RFC 3849 (2001:db8::/32) are reserved for
# documentation and will never host real services.  65535 is an invalid port
# so connections refuse immediately — tools start, parse args, then exit fast.
_TARGET_FOR: dict[TargetType, str] = {
    TargetType.URL: "http://192.0.2.1:65535/",
    TargetType.HOST: "192.0.2.1",
    TargetType.IP: "192.0.2.1",
    TargetType.CIDR: "192.0.2.0/30",
    TargetType.PATH: "/tmp/vs_invtest",
    TargetType.REPO: "/tmp/vs_invtest",
    # CLOUD: real cloud tools need real credentials; skip them in the invocation test
    # TargetType.CLOUD is intentionally absent — tools with only CLOUD target get skipped
}

_EXECUTION_TIMEOUT = 15  # seconds — long enough for JVM startup; bad-arg exits in <1 s
_WORKERS = 30  # parallel tool invocations
_MODE = ScanMode.PASSIVE

# Strings that indicate a tool rejected our CLI arguments.
# Checked case-insensitively in the first 60 lines of combined stdout+stderr.
_BAD_ARG_MARKERS = (
    "unrecognized argument",
    "unrecognized arguments",
    "unknown flag",
    "unknown shorthand flag",
    "invalid argument",
    "invalid option",
    "no such option",
    "error: argument",
    "error: unrecognized",
    "error: invalid option",   # flag-level error only; avoids matching resource-not-found
    "error: invalid choice",   # argparse choice error
    "illegal option",
    "unexpected argument",
    "does not accept",
)

# ── Result types ──────────────────────────────────────────────────────────────

STATUS_OK = "ok"
STATUS_SKIPPED = "skipped"
STATUS_MISSING = "missing"
STATUS_BAD_FLAGS = "bad_flags"
STATUS_ERROR = "error"

_STATUS_COLOR = {
    STATUS_OK: "\033[32m",  # green
    STATUS_SKIPPED: "\033[33m",  # yellow
    STATUS_MISSING: "\033[31m",  # red
    STATUS_BAD_FLAGS: "\033[31m",  # red
    STATUS_ERROR: "\033[31m",  # red
}
_RESET = "\033[0m"


@dataclass
class InvResult:
    name: str
    status: str
    target: str = ""
    detail: str = ""
    output_snippet: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────


def _pick_target(cls: type) -> str | None:
    """Return the most appropriate fake target, or None if no fake target covers this tool."""
    applicable = cls.model_fields["applicable_targets"].default
    if applicable is _ALL_TARGET_TYPES or not applicable:
        return _TARGET_FOR[TargetType.URL]
    priority = (
        TargetType.URL,
        TargetType.HOST,
        TargetType.IP,
        TargetType.CIDR,
        TargetType.PATH,
        TargetType.REPO,
    )
    for tt in priority:
        if tt in applicable:
            return _TARGET_FOR[tt]
    # No matching fake target (e.g. CLOUD-only tools) — caller should skip.
    return None


def _detect_bad_flags(raw: str) -> tuple[bool, str]:
    """Return (True, offending_line) if the output contains a flag-rejection message."""
    lines = raw.splitlines()[:60]
    head_lower = "\n".join(lines).lower()
    for marker in _BAD_ARG_MARKERS:
        if marker in head_lower:
            for line in lines:
                if marker in line.lower():
                    return True, line.strip()
    return False, ""


# ── Core invocation ───────────────────────────────────────────────────────────


def _invoke(tool_name: str) -> InvResult:
    cls = TOOL_REGISTRY[tool_name]
    binary: str = cls.model_fields["binary"].default or ""

    if not binary:
        return InvResult(name=tool_name, status=STATUS_SKIPPED, detail="no binary (API-only)")

    target = _pick_target(cls)
    if target is None:
        applicable = cls.model_fields["applicable_targets"].default
        return InvResult(name=tool_name, status=STATUS_SKIPPED,
                         detail=f"no fake target for {set(applicable)}")
    scan_input = ScanInput(targets=[target], timeout=_EXECUTION_TIMEOUT, mode=_MODE)
    tool = cls()

    try:
        result = tool.run(target, scan_input)
    except Exception as exc:
        return InvResult(
            name=tool_name,
            status=STATUS_ERROR,
            target=target,
            detail=f"Exception: {type(exc).__name__}: {exc}",
        )

    raw = result.raw_output or ""
    err = result.error or ""

    # Capture raw output for all non-ok results so failures are diagnosable.
    snippet = (raw or err)[:800].strip()

    # 1. Binary not found — FileNotFoundError path, shell "command not found", or
    #    dynamic linker failure ("cannot open shared object file").
    #    NOTE: ": not found" and "exit code 126" are intentionally excluded:
    #    ": not found" matches application-level file errors (e.g. cargo-audit's
    #    "Couldn't load Cargo.lock … entity not found"); exit 126 is kics's own
    #    error code for "scan completed with errors", not a missing binary.
    _MISSING_MARKERS = (
        "binary not found",           # abstract.py FileNotFoundError handler
        "command not found",          # sh: <cmd>: command not found
        "no such file or directory",  # dynamic linker / ld-linux failures
        "exit code 127",              # sh: exec: <cmd>: not found
    )
    if result.status == ScanStatus.FAILED:
        err_low = err.lower()
        if any(m in err_low for m in _MISSING_MARKERS):
            return InvResult(name=tool_name, status=STATUS_MISSING, target=target,
                             detail=err, output_snippet=snippet)

    # 1b. Python import/dependency errors — tool ran but crashed during startup
    _PYTHON_ERR_MARKERS = (
        "modulenotfounderror",
        "importerror:",
        "no module named",
        "cannot import name",
    )
    combined_low = (raw + err).lower()
    if result.status == ScanStatus.FAILED and any(m in combined_low for m in _PYTHON_ERR_MARKERS):
        return InvResult(name=tool_name, status=STATUS_ERROR, target=target,
                         detail=f"Python import error: {err[:120] or raw[:120]}",
                         output_snippet=snippet)

    # 2. Check combined output + error field for flag-rejection markers
    for text in (raw, err):
        bad, bad_line = _detect_bad_flags(text)
        if bad:
            return InvResult(
                name=tool_name,
                status=STATUS_BAD_FLAGS,
                target=target,
                detail=bad_line,
                output_snippet=snippet,
            )

    # 3. Tool started and either completed, timed out, or failed for a real reason
    #    (unreachable target, connection refused, etc.) — all considered OK.
    exit_info = result.status.value
    if result.status == ScanStatus.FAILED and err:
        exit_info = f"failed: {err[:80]}"
        return InvResult(name=tool_name, status=STATUS_OK, target=target,
                         detail=exit_info, output_snippet=snippet)
    return InvResult(name=tool_name, status=STATUS_OK, target=target, detail=exit_info)


# ── Reporting ─────────────────────────────────────────────────────────────────


def _print_table(results: list[InvResult], verbose: bool) -> None:
    w = max(len(r.name) for r in results)
    print(f"\n{'TOOL':<{w}}  {'STATUS':<12}  DETAIL")
    print("-" * (w + 55))
    for r in results:
        is_failure = r.status in (STATUS_BAD_FLAGS, STATUS_MISSING, STATUS_ERROR)
        if not verbose and not is_failure:
            continue
        color = _STATUS_COLOR.get(r.status, "")
        label = r.status.upper().replace("_", " ")
        detail = r.detail or r.target
        print(f"{r.name:<{w}}  {color}{label:<12}{_RESET}  {detail}")
        if r.output_snippet and is_failure:
            print(textwrap.indent(r.output_snippet.rstrip(), "      "))
            print()


def _print_summary(results: list[InvResult]) -> None:
    from collections import Counter

    counts = Counter(r.status for r in results)
    ok = counts[STATUS_OK]
    skipped = counts[STATUS_SKIPPED]
    bad = counts[STATUS_BAD_FLAGS] + counts[STATUS_MISSING] + counts[STATUS_ERROR]
    print(f"\nResults: {ok} ok  |  {skipped} skipped (no binary)  |  {bad} failed")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all tools, not just failures.")
    parser.add_argument("--tool", nargs="+", metavar="NAME", help="Only run specific tool(s).")
    parser.add_argument("--workers", type=int, default=_WORKERS, metavar="N")
    parser.add_argument("--timeout", type=int, default=_EXECUTION_TIMEOUT, metavar="SECONDS")
    args = parser.parse_args()

    # Prepare temp directories used as fake PATH/REPO targets.
    for tt in (TargetType.PATH, TargetType.REPO):
        Path(_TARGET_FOR[tt]).mkdir(parents=True, exist_ok=True)
    # Create a stub APK file so mobile tools (quark, qark) find a file to inspect.
    stub_apk = Path(_TARGET_FOR[TargetType.PATH]) / "app.apk"
    stub_apk.touch(exist_ok=True)

    tool_names = sorted(args.tool or TOOL_REGISTRY)
    invalid = [n for n in tool_names if n not in TOOL_REGISTRY]
    if invalid:
        print(f"Unknown tool(s): {', '.join(invalid)}", file=sys.stderr)
        return 1

    timeout = args.timeout
    # Hard per-future deadline: tool timeout + a small grace period for process cleanup.
    future_deadline = timeout + 5

    print(f"Invoking {len(tool_names)} tool(s)  timeout={timeout}s  workers={args.workers}")
    print("Legend: . ok  s skipped  F bad-flags  M missing  E error\n")

    _SYM = {STATUS_OK: ".", STATUS_SKIPPED: "s", STATUS_BAD_FLAGS: "F",
             STATUS_MISSING: "M", STATUS_ERROR: "E"}

    results: list[InvResult] = []

    def _invoke_with_timeout(name: str) -> InvResult:
        # Override the module-level default so callers of _invoke see args.timeout.
        global _EXECUTION_TIMEOUT
        _EXECUTION_TIMEOUT = timeout
        return _invoke(name)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
    futures = {pool.submit(_invoke_with_timeout, name): name for name in tool_names}
    done = 0
    try:
        for future in concurrent.futures.as_completed(futures, timeout=future_deadline * len(tool_names)):
            done += 1
            try:
                res = future.result(timeout=future_deadline)
            except concurrent.futures.TimeoutError:
                name = futures[future]
                res = InvResult(name=name, status=STATUS_ERROR,
                                detail=f"hard deadline {future_deadline}s exceeded (subprocess hung)")
            results.append(res)
            sym = _SYM.get(res.status, "?")
            if res.status == STATUS_MISSING:
                # Print name inline so missing binaries are visible without --verbose.
                print(f"\nM  {res.name}: {res.detail.splitlines()[0][:100]}", flush=True)
            elif res.status in (STATUS_BAD_FLAGS, STATUS_ERROR):
                print(f"\n{sym}  {res.name}: {res.detail[:100]}", flush=True)
            else:
                print(sym, end="", flush=True)
            if done % 50 == 0:
                print(f"  {done}/{len(tool_names)}")
    except (KeyboardInterrupt, concurrent.futures.TimeoutError):
        # Print partial results and exit cleanly.
        remaining = [futures[f] for f in futures if not f.done()]
        if remaining:
            print(f"\n[interrupted — {len(remaining)} tool(s) still running: {', '.join(remaining[:5])}{'…' if len(remaining) > 5 else ''}]")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    print()

    results.sort(
        key=lambda r: (r.status != STATUS_BAD_FLAGS, r.status != STATUS_MISSING, r.status != STATUS_ERROR, r.name)
    )

    _print_table(results, args.verbose)
    _print_summary(results)

    failures = [r for r in results if r.status in (STATUS_BAD_FLAGS, STATUS_MISSING, STATUS_ERROR)]
    if failures:
        print(f"\nFailed ({len(failures)}):")
        for r in failures:
            print(f"  [{r.status.upper().replace('_', '-')}] {r.name}: {r.detail}")
        return 1

    print("\nAll invoked tools passed.")
    return 0


if __name__ == "__main__":
    import os as _os
    # os._exit bypasses atexit/thread-join so hung tool threads don't block shutdown.
    _os._exit(main())
