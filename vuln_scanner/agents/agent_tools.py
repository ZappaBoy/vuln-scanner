"""Agent tool implementations — the callable surface an agent uses.

These are plain functions taking ``AgentDeps`` + args so they are unit-testable
without an LLM.  The runner (M4) wraps them as Pydantic AI tools.  Every
host-touching function routes through the M2 guards (container gate, scope,
denylist, audit) before acting.
"""

import json
import logging
import shutil
import time

from vuln_scanner.agents.audit import _MAX_FIELD, _truncate
from vuln_scanner.agents.deps import AgentDeps, ContainerGateError, ScopeViolation
from vuln_scanner.agents.guards import denylist_check
from vuln_scanner.agents.models import AgentFinding, AgentKind, AgentNote, AgentPoc, CodeLanguage
from vuln_scanner.agents.sandbox import run_code_sandboxed

log = logging.getLogger(__name__)

_DEFAULT_EXEC_TIMEOUT = 300
_DEFAULT_HTTP_TIMEOUT = 30
_POC_ID_PREFIX = "agent-poc-"

_STOP_DEADLINE = "STOP: time budget exhausted — finalize and summarize your findings now."
_STOP_CEILING = "STOP: tool-call ceiling reached — finalize and summarize your findings now."

# Scratchpad caps so a runaway agent cannot blow memory / tokens.
_MAX_NOTES = 200
_MAX_NOTE_LEN = _MAX_FIELD  # per-note text cap; reuse the audit truncation width
_MAX_RESP_BYTES = 16384  # captured response-body cap; matches the sandbox output cap
_HTTP_CHUNK_BYTES = 4096  # streamed response read size

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_HTTP_METHODS = _SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}


def _remaining_timeout(deps: AgentDeps, default: int) -> int:
    """Per-call timeout, capped by the run's remaining wall-clock budget."""
    if deps.deadline is None:
        return default
    remaining = int(deps.deadline - time.monotonic())
    return max(1, min(default, remaining))


def _precheck(deps: AgentDeps, tool: str) -> str | None:
    """Shared gate for every agent tool. Returns an error string if blocked."""
    if deps.past_deadline():
        return _STOP_DEADLINE
    if deps.ceiling_reached():
        return _STOP_CEILING
    allowed = deps.agent.allowed_tools
    if allowed and tool not in allowed:
        return f"Tool '{tool}' is not permitted for this agent."
    if tool in deps.agent.denied_tools:
        return f"Tool '{tool}' is denied for this agent."
    deps.bump_tool_call()
    return None


# ── list_tools ────────────────────────────────────────────────────────────────


def list_tools(deps: AgentDeps, category: str = "") -> str:
    """List installed scanner tools the agent can drive with ``run_tool``."""
    from vuln_scanner.tools import TOOL_REGISTRY

    lines: list[str] = []
    for name, cls in sorted(TOOL_REGISTRY.items()):
        try:
            instance = cls()
        except Exception:
            continue
        if category and instance.category != category:
            continue
        binary = instance.binary or name
        if shutil.which(binary) is None:
            continue
        lines.append(f"{name} [{instance.category}] → {binary}")
    deps.audit.record("list_tools", category=category, count=len(lines))
    return "\n".join(lines) if lines else "No installed tools match."


# ── run_tool ──────────────────────────────────────────────────────────────────


def run_tool(deps: AgentDeps, tool_name: str, args: list[str], target: str = "") -> dict:
    """Run an installed tool binary with custom *args*.

    *target* (if given) is used only for scope validation.  Returns raw
    stdout/stderr/exit_code for the agent to reason over.
    """
    blocked = _precheck(deps, "run_tool")
    if blocked:
        return {"error": blocked}

    from vuln_scanner.tools import TOOL_REGISTRY

    cls = TOOL_REGISTRY.get(tool_name)
    if cls is None:
        return {"error": f"Unknown tool '{tool_name}'. Use list_tools to see options."}

    joined = " ".join(args)
    safe, reason = denylist_check(joined)
    if not safe:
        deps.audit.record("run_tool", tool=tool_name, refused=reason, args=args)
        return {"error": f"Refused: {reason}"}

    try:
        deps.require_container("run_tool")
        deps.assert_in_scope(target, joined)
    except ContainerGateError as exc:
        return {"error": str(exc)}
    except ScopeViolation as exc:
        return {"error": str(exc)}

    tool = cls()
    timeout = _remaining_timeout(deps, _DEFAULT_EXEC_TIMEOUT)
    result = tool.exec(args, timeout=timeout, target=target or None)
    deps.audit.record(
        "run_tool",
        tool=tool_name,
        target=target,
        args=args,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    return {
        "tool": tool_name,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
    }


# ── run_code ──────────────────────────────────────────────────────────────────


def run_code(deps: AgentDeps, language: str, code: str) -> dict:
    """Execute agent-authored *code* in the hardened sandbox.

    For a pentester without live-exploitation clearance the code is NOT run —
    it is recorded as a dry-run exploit-plan step and returned as such.
    """
    blocked = _precheck(deps, "run_code")
    if blocked:
        return {"error": blocked}

    # Scope-check any host literal in the code before anything runs.
    try:
        deps.assert_in_scope(code)
    except ScopeViolation as exc:
        deps.audit.record("run_code", refused="scope", language=language)
        return {"error": str(exc)}

    # Pentester dry-run gate: record the plan instead of executing.
    if deps.agent.kind == AgentKind.PENTESTER and not deps.live_exploit_allowed:
        deps.exploit_plan.append(f"[{language}] {code}")
        deps.audit.record("run_code", mode="dry_run", language=language, code=code)
        return {
            "executed": False,
            "note": "Recorded as dry-run exploit-plan step (live exploitation not authorized).",
        }

    result = run_code_sandboxed(
        language,
        code,
        sandbox=deps.agents_cfg.sandbox,
        allowed_languages=deps.code_languages,
    )
    deps.audit.record(
        "run_code",
        language=language,
        code=code,
        blocked=result.blocked,
        block_reason=result.block_reason,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    if result.blocked:
        return {"executed": False, "error": f"Blocked: {result.block_reason}"}
    return {
        "executed": True,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ── http_request ──────────────────────────────────────────────────────────────


def _format_request(method: str, url: str, headers: dict[str, str], body: str) -> str:
    """Render a request as HTTP-wire-like evidence, ready for save_bug.request."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    lines = [f"{method} {path} HTTP/1.1"]
    if parts.netloc:
        lines.append(f"Host: {parts.hostname or parts.netloc}")
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def _format_response(status_code: int, reason: str, headers: dict[str, str], body: str, truncated: bool) -> str:
    """Render a response as HTTP-wire-like evidence, ready for save_bug.response."""
    lines = [f"HTTP/1.1 {status_code} {reason}".rstrip()]
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    lines.append("")
    lines.append(body)
    if truncated:
        lines.append(f"… [response truncated at {_MAX_RESP_BYTES} bytes]")
    return "\n".join(lines)


def http_request(
    deps: AgentDeps,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    follow_redirects: bool = False,
) -> dict:
    """Send one scoped HTTP(S) request and capture raw request/response evidence.

    The core in-band bug-bounty primitive: craft a request, observe the
    response.  Routes through the same guards as ``run_tool`` — ceiling/
    deadline, allow/deny filter, denylist (url + body), container gate, and
    scope — then returns HTTP-wire-shaped ``request``/``response`` strings that
    drop straight into :func:`save_bug`.  For a pentester without live-
    exploitation clearance, a mutating method (POST/PUT/PATCH/DELETE) is NOT
    sent: it is recorded as a dry-run exploit-plan step, mirroring ``run_code``.
    """
    blocked = _precheck(deps, "http_request")
    if blocked:
        return {"error": blocked}

    method = (method or "GET").strip().upper()
    if method not in _HTTP_METHODS:
        return {"error": f"Unsupported HTTP method {method!r}. Use one of {sorted(_HTTP_METHODS)}."}

    safe, reason = denylist_check(f"{url}\n{body}")
    if not safe:
        deps.audit.record("http_request", refused=reason, method=method, url=url)
        return {"error": f"Refused: {reason}"}

    try:
        deps.require_container("http_request")
        deps.assert_in_scope(url)
    except ContainerGateError as exc:
        return {"error": str(exc)}
    except ScopeViolation as exc:
        return {"error": str(exc)}

    request_headers = {str(name): str(value) for name, value in (headers or {}).items()}

    # Pentester dry-run gate: a mutating request is a state change → record, don't send.
    if deps.agent.kind == AgentKind.PENTESTER and not deps.live_exploit_allowed and method not in _SAFE_METHODS:
        step = _format_request(method, url, request_headers, body)
        deps.exploit_plan.append(step)
        deps.audit.record("http_request", mode="dry_run", method=method, url=url)
        return {
            "executed": False,
            "note": "Recorded as dry-run exploit-plan step (mutating request; live exploitation not authorized).",
            "request": step,
        }

    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # lab targets: self-signed certs

    timeout = _remaining_timeout(deps, _DEFAULT_HTTP_TIMEOUT)
    try:
        response = requests.request(
            method,
            url,
            headers=request_headers or None,
            data=body.encode("utf-8", "replace") if body else None,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=False,  # in-scope lab hosts frequently use self-signed certs
            stream=True,
        )
    except requests.RequestException as exc:
        deps.audit.record("http_request", method=method, url=url, error=str(exc))
        return {"error": f"Request failed: {exc}"}

    try:
        total_bytes = 0
        chunks: list[bytes] = []
        for chunk in response.iter_content(chunk_size=_HTTP_CHUNK_BYTES):
            chunks.append(chunk)
            total_bytes += len(chunk)
            if total_bytes > _MAX_RESP_BYTES:
                break
        raw_body = b"".join(chunks)
        truncated = total_bytes > _MAX_RESP_BYTES
        body_text = raw_body[:_MAX_RESP_BYTES].decode(response.encoding or "utf-8", "replace")
        response_headers = dict(response.headers)
        status_code = response.status_code
        reason = response.reason or ""
        final_url = response.url
    finally:
        response.close()

    deps.audit.record(
        "http_request",
        method=method,
        url=url,
        status=status_code,
        bytes=total_bytes,
        response=body_text,
    )
    return {
        "status_code": status_code,
        "url": final_url,
        "response_headers": response_headers,
        "body": body_text,
        "truncated": truncated,
        "request": _format_request(method, url, request_headers, body),
        "response": _format_response(status_code, reason, response_headers, body_text, truncated),
    }


# ── save_bug ──────────────────────────────────────────────────────────────────


def save_bug(deps: AgentDeps, bug: AgentFinding) -> str:
    """Persist a confirmed bug (evidence of existence) for reporting/submission."""
    bug.discovered_by = deps.agent.name
    deps.findings.append(bug)
    deps.audit.record("save_bug", title=bug.title, severity=bug.severity.value, target=bug.target)
    return f"Saved bug #{len(deps.findings)}: {bug.title} [{bug.severity.value}]"


# ── record_poc ────────────────────────────────────────────────────────────────


def record_poc(deps: AgentDeps, poc: AgentPoc, script: str = "") -> str:
    """Record a PoC artifact; writes *script* (if any) to the agent artifact dir."""
    poc.id = f"{_POC_ID_PREFIX}{len(deps.pocs) + 1:03d}"
    if script.strip():
        path = deps.artifact_dir / f"{poc.id}{CodeLanguage.extension_for(poc.language)}"
        try:
            deps.artifact_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(script, encoding="utf-8")
            poc.script_path = str(path)
        except OSError as exc:  # pragma: no cover - defensive
            log.warning("PoC write failed: %s", exc)
    deps.pocs.append(poc)
    deps.audit.record("record_poc", id=poc.id, finding=poc.finding_title, verdict=poc.verdict)
    return f"Recorded {poc.id} for '{poc.finding_title}' (verdict: {poc.verdict})"


# ── OOB / OAST ────────────────────────────────────────────────────────────────


def oob_get_callback(deps: AgentDeps) -> str:
    """Return a unique OOB callback domain to inject into payloads."""
    blocked = _precheck(deps, "oob_get_callback")
    if blocked:
        return blocked
    try:
        deps.require_container("oob_get_callback")
    except ContainerGateError as exc:
        return str(exc)

    if deps.oob_session is None:
        from vuln_scanner.agents.oob import OobSession

        session = OobSession(server=deps.oob_server, token=deps.oob_token)
        session.start()
        deps.oob_session = session

    deps.audit.record("oob_get_callback", domain=deps.oob_session.domain, available=deps.oob_session.available)
    if not deps.oob_session.available:
        return "OOB unavailable (interactsh-client not running). Use a direct-evidence technique instead."
    return deps.oob_session.domain


def oob_check(deps: AgentDeps) -> dict:
    """Poll for OOB interactions observed since the last check."""
    blocked = _precheck(deps, "oob_check")
    if blocked:
        return {"error": blocked}
    if deps.oob_session is None or not deps.oob_session.available:
        return {"interactions": [], "note": "No active OOB session."}
    new_interactions = deps.oob_session.check()
    deps.audit.record("oob_check", new_interactions=len(new_interactions))
    return {"interactions": new_interactions, "count": len(new_interactions)}


# ── note / recall (agent scratchpad) ───────────────────────────────────────────


def _persist_note(deps: AgentDeps, entry: AgentNote) -> None:
    """Best-effort append of a note to ``<agent>.notes.jsonl`` beside the action log.

    Gives the scratchpad the same post-hoc auditability as the action log without
    ever surfacing raw notes into the submission report.  Never raises — a
    notes-write failure must not crash an agent run.
    """
    path = deps.audit.path.parent / f"{deps.audit.path.stem}.notes.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.model_dump(), ensure_ascii=False, default=str) + "\n")
    except OSError as exc:  # pragma: no cover - defensive
        log.warning("Notes log write failed for %s: %s", deps.agent.name, exc)


def note(deps: AgentDeps, text: str, tag: str = "") -> str:
    """Record a working-memory note to the run's scratchpad.

    A lightweight, persistent scratchpad for intermediate observations
    (discovered endpoints, params, hypotheses, credentials-to-retest) that
    should survive across tool calls without being burned into the final
    summary.  Network-free — it never contacts a host, so there is no scope or
    container gate — but it still goes through :func:`_precheck` (ceiling/
    deadline, allow/deny filter) and is audited.
    """
    blocked = _precheck(deps, "note")
    if blocked:
        return blocked

    text = (text or "").strip()
    if not text:
        return "Empty note ignored — pass text to record."
    if len(deps.notes) >= _MAX_NOTES:
        deps.audit.record("note", refused="cap", cap=_MAX_NOTES)
        return f"Scratchpad full ({_MAX_NOTES} notes) — recall and consolidate before adding more."

    tag = (tag or "").strip()
    entry = AgentNote(seq=len(deps.notes) + 1, tag=tag, text=_truncate(text))
    deps.notes.append(entry)
    deps.audit.record("note", seq=entry.seq, tag=entry.tag, text=entry.text)
    _persist_note(deps, entry)
    return f"Noted #{entry.seq}" + (f" [{entry.tag}]" if entry.tag else "")


def recall(deps: AgentDeps, tag: str = "") -> str:
    """Return the scratchpad notes recorded so far, oldest first.

    Optionally filter by *tag*.  Read these back before summarizing so nothing
    discovered mid-run is lost when the context window rolls.
    """
    blocked = _precheck(deps, "recall")
    if blocked:
        return blocked

    tag = (tag or "").strip()
    entries = [entry for entry in deps.notes if not tag or entry.tag == tag]
    deps.audit.record("recall", tag=tag, count=len(entries))
    if not entries:
        scope = f" tagged [{tag}]" if tag else ""
        return f"No notes recorded{scope} yet."

    lines = [
        f"#{entry.seq}" + (f" [{entry.tag}]" if entry.tag else "") + f": {entry.text}" for entry in entries
    ]
    return "\n".join(lines)
