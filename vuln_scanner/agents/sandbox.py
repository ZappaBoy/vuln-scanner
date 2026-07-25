"""Hardened execution sandbox for agent-authored code (``run_code``).

Applies POSIX resource limits (CPU, address space, process count, file size) in
the child before exec so a runaway / fork bomb / disk filler cannot take down
the host even if the denylist misses it.  Container-only; the denylist and the
caller's scope host-scan are additional layers.

Network isolation ("none"/"lab") is enforced at the container/compose layer
(namespace + egress policy); this module records the requested policy and relies
on the caller's scope validation of any host literal in the code.
"""

import logging
import os
import resource
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from pydantic import BaseModel

from vuln_scanner.agents.guards import denylist_check, is_in_container
from vuln_scanner.agents.models import SandboxConfig

log = logging.getLogger(__name__)

# language → (file extension, interpreter argv prefix)
_LANG_RUNNERS: dict[str, tuple[str, list[str]]] = {
    "python": (".py", ["python3"]),
    "bash": (".sh", ["bash"]),
    "sh": (".sh", ["sh"]),
    "ruby": (".rb", ["ruby"]),
    "perl": (".pl", ["perl"]),
    "php": (".php", ["php"]),
    "javascript": (".js", ["node"]),
    "node": (".js", ["node"]),
}

_OUT_TRUNCATE = 16384


class SandboxResult(BaseModel):
    language: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration: float = 0.0
    blocked: bool = False  # refused before execution
    block_reason: str = ""
    network: str = ""


def _rlimit_preexec(cfg: SandboxConfig):
    """Return a preexec_fn that applies rlimits + a new session in the child."""

    def _apply() -> None:  # pragma: no cover - runs in forked child
        os.setsid()
        # CPU seconds (SIGXCPU then SIGKILL)
        resource.setrlimit(resource.RLIMIT_CPU, (cfg.cpu_seconds, cfg.cpu_seconds + 1))
        # Address space / virtual memory
        mem = cfg.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        # Max processes (fork-bomb guard)
        resource.setrlimit(resource.RLIMIT_NPROC, (cfg.max_procs, cfg.max_procs))
        # Max file size the process may create
        fsize = cfg.file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        # No core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _apply


def run_code_sandboxed(
    language: str,
    code: str,
    *,
    sandbox: SandboxConfig,
    allowed_languages: list[str],
    workdir: Path | None = None,
) -> SandboxResult:
    """Execute *code* in *language* under resource limits.

    Refuses (``blocked=True``) outside the container, for unsupported or
    disallowed languages, or on a denylist match — before running anything.
    """
    lang = language.lower().strip()

    if not is_in_container():
        return SandboxResult(
            language=lang, blocked=True, block_reason="not_in_container", network=sandbox.network
        )
    if allowed_languages and lang not in [x.lower() for x in allowed_languages]:
        return SandboxResult(
            language=lang, blocked=True, block_reason=f"language '{lang}' not allowed", network=sandbox.network
        )
    if lang not in _LANG_RUNNERS:
        return SandboxResult(
            language=lang, blocked=True, block_reason=f"unsupported language '{lang}'", network=sandbox.network
        )

    safe, reason = denylist_check(code)
    if not safe:
        log.warning("run_code denylist block: %s", reason)
        return SandboxResult(language=lang, blocked=True, block_reason=reason, network=sandbox.network)

    ext, runner = _LANG_RUNNERS[lang]
    wd = workdir or Path(tempfile.mkdtemp(prefix="vs_agent_sbx_"))
    wd.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=ext, prefix="code_", dir=str(wd))
    os.close(fd)
    Path(tmp).write_text(code, encoding="utf-8")

    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            runner + [tmp],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(wd),
            preexec_fn=_rlimit_preexec(sandbox),
        )
        try:
            stdout, stderr = proc.communicate(timeout=sandbox.timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                proc.kill()
            stdout, stderr = proc.communicate()
            return SandboxResult(
                language=lang,
                stdout=(stdout or "")[:_OUT_TRUNCATE],
                stderr=(stderr or "")[:_OUT_TRUNCATE],
                timed_out=True,
                duration=float(sandbox.timeout),
                network=sandbox.network,
            )

        return SandboxResult(
            language=lang,
            exit_code=proc.returncode,
            stdout=(stdout or "")[:_OUT_TRUNCATE],
            stderr=(stderr or "")[:_OUT_TRUNCATE],
            duration=time.monotonic() - start,
            network=sandbox.network,
        )
    except FileNotFoundError:
        return SandboxResult(
            language=lang,
            blocked=True,
            block_reason=f"interpreter not found: {runner[0]}",
            network=sandbox.network,
        )
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
