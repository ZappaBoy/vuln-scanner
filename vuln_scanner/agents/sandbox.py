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

from vuln_scanner.agents.guards import denylist_check, is_in_container
from vuln_scanner.agents.models import CodeLanguage, SandboxConfig, SandboxResult

log = logging.getLogger(__name__)

# Interpreter argv prefix for each supported language.
_INTERPRETERS: dict[CodeLanguage, list[str]] = {
    CodeLanguage.PYTHON: ["python3"],
    CodeLanguage.BASH: ["bash"],
    CodeLanguage.SH: ["sh"],
    CodeLanguage.RUBY: ["ruby"],
    CodeLanguage.PERL: ["perl"],
    CodeLanguage.PHP: ["php"],
    CodeLanguage.JAVASCRIPT: ["node"],
    CodeLanguage.NODE: ["node"],
}

_OUT_TRUNCATE = 16384

_BLOCK_NOT_IN_CONTAINER = "not_in_container"
_TEMP_WORKDIR_PREFIX = "vs_agent_sbx_"
_TEMP_CODE_PREFIX = "code_"


def _rlimit_preexec(config: SandboxConfig):
    """Return a preexec_fn that applies rlimits + a new session in the child."""

    def _apply() -> None:  # pragma: no cover - runs in forked child
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (config.cpu_seconds, config.cpu_seconds + 1))
        memory_bytes = config.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (config.max_procs, config.max_procs))
        file_size_bytes = config.file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
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
    name = language.lower().strip()
    network = sandbox.network.value

    if not is_in_container():
        return SandboxResult(language=name, blocked=True, block_reason=_BLOCK_NOT_IN_CONTAINER, network=network)
    if allowed_languages and name not in [allowed.lower() for allowed in allowed_languages]:
        return SandboxResult(
            language=name, blocked=True, block_reason=f"language '{name}' not allowed", network=network
        )
    code_language = CodeLanguage.from_name(name)
    if code_language is None:
        return SandboxResult(
            language=name, blocked=True, block_reason=f"unsupported language '{name}'", network=network
        )

    safe, reason = denylist_check(code)
    if not safe:
        log.warning("run_code denylist block: %s", reason)
        return SandboxResult(language=name, blocked=True, block_reason=reason, network=network)

    interpreter = _INTERPRETERS[code_language]
    work_dir = workdir or Path(tempfile.mkdtemp(prefix=_TEMP_WORKDIR_PREFIX))
    work_dir.mkdir(parents=True, exist_ok=True)
    file_descriptor, code_path = tempfile.mkstemp(
        suffix=code_language.extension, prefix=_TEMP_CODE_PREFIX, dir=str(work_dir)
    )
    os.close(file_descriptor)
    Path(code_path).write_text(code, encoding="utf-8")

    start = time.monotonic()
    try:
        process = subprocess.Popen(
            interpreter + [code_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(work_dir),
            preexec_fn=_rlimit_preexec(sandbox),
        )
        try:
            stdout, stderr = process.communicate(timeout=sandbox.timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                process.kill()
            stdout, stderr = process.communicate()
            return SandboxResult(
                language=name,
                stdout=(stdout or "")[:_OUT_TRUNCATE],
                stderr=(stderr or "")[:_OUT_TRUNCATE],
                timed_out=True,
                duration=float(sandbox.timeout),
                network=network,
            )

        return SandboxResult(
            language=name,
            exit_code=process.returncode,
            stdout=(stdout or "")[:_OUT_TRUNCATE],
            stderr=(stderr or "")[:_OUT_TRUNCATE],
            duration=time.monotonic() - start,
            network=network,
        )
    except FileNotFoundError:
        return SandboxResult(
            language=name,
            blocked=True,
            block_reason=f"interpreter not found: {interpreter[0]}",
            network=network,
        )
    finally:
        try:
            os.unlink(code_path)
        except OSError:
            pass
