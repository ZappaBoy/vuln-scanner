#!/usr/bin/env python3
"""Verify that every tool's declared binary (or Python script) is present.

Run inside the Docker image:
    docker run --rm <image> python3 tests/check_binaries.py

Exit code 0  → all binaries / scripts found (API-only tools are skipped).
Exit code 1  → one or more binaries / scripts missing.
"""

import inspect
import os
import re
import shutil
import sys

from vuln_scanner.tools import TOOL_REGISTRY
from vuln_scanner.tools.models import ScanInput

_SCRIPT_RE = re.compile(r'"(/opt/[^"]+\.py)"')

OK = "\033[32mOK\033[0m"
MISSING = "\033[31mMISSING\033[0m"
SKIPPED = "\033[33mSKIPPED\033[0m"


def _python3_script(cls: type) -> str:
    """Return the Python script path for a python3-binary tool, or '' if not found."""
    # Try build_command with a throwaway target
    try:
        inst = cls()
        cmd = inst.build_command("example.com", ScanInput(targets=["example.com"]))
        if cmd and len(cmd) >= 2 and cmd[1].endswith(".py"):
            return cmd[1]
    except Exception:
        pass

    # Fallback: scan class source for "/opt/.../*.py" literals (covers custom run() tools)
    try:
        m = _SCRIPT_RE.search(inspect.getsource(cls))
        if m:
            return m.group(1)
    except Exception:
        pass

    return ""


def _check(binary: str, cls: type) -> tuple[bool, str]:
    """Return (found, detail) where detail is the path/binary that was checked."""
    if binary == "python3":
        script = _python3_script(cls)
        if script:
            return os.path.isfile(script), script
        # No script path found — just verify python3 is present
        return bool(shutil.which("python3")), "python3 (no script path found)"
    return bool(shutil.which(binary)), binary


def main() -> int:
    rows: list[tuple[str, str, str, str]] = []  # (tool_name, detail, plain_status, colored_status)

    for tool_name in sorted(TOOL_REGISTRY):
        cls = TOOL_REGISTRY[tool_name]
        binary: str = cls.model_fields["binary"].default or ""

        if not binary:
            rows.append((tool_name, "—", "SKIPPED", SKIPPED))
            continue

        found, detail = _check(binary, cls)
        plain = "OK" if found else "MISSING"
        colored = OK if found else MISSING
        rows.append((tool_name, detail, plain, colored))

    w_name = max(len(r[0]) for r in rows)
    w_detail = max(len(r[1]) for r in rows)

    header = f"{'TOOL':<{w_name}}  {'BINARY / SCRIPT':<{w_detail}}  STATUS"
    print(header)
    print("-" * (w_name + w_detail + 12))

    missing: list[str] = []
    for tool_name, detail, plain, colored in rows:
        print(f"{tool_name:<{w_name}}  {detail:<{w_detail}}  {colored}")
        if plain == "MISSING":
            missing.append(f"{tool_name} ({detail})")

    print()
    total = len(rows)
    skipped = sum(1 for r in rows if r[2] == "SKIPPED")
    checked = total - skipped
    found = checked - len(missing)

    print(f"Results: {found}/{checked} binaries found  ({skipped} API-only tools skipped)")

    if missing:
        print(f"\nMissing ({len(missing)}):")
        for m in missing:
            print(f"  - {m}")
        return 1

    print("\nAll binaries present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
