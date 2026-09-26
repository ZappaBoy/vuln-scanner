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
from vuln_scanner.agents.models import AgentFinding, AgentKind, AgentPoc
from vuln_scanner.agents.sandbox import run_code_sandboxed
from vuln_scanner.tools.enums import Severity, _parse_severity

log = logging.getLogger(__name__)

_DEFAULT_EXEC_TIMEOUT = 300
_DEFAULT_HTTP_TIMEOUT = 30
_MAX_NOTES = 200  # cap scratchpad size so a runaway agent can't blow memory/tokens
_MAX_NOTE_LEN = _MAX_FIELD  # per-note text cap (reuse audit truncation width)
_MAX_RESP_BYTES = 16384  # cap captured response body (matches sandbox _OUT_TRUNCATE)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_HTTP_METHODS = _SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
_STATE_LIST_LIMIT = 50  # cap items returned by read_state so shared state can't blow the context
_MAX_OBJECTIVE_LEN = 2000  # cap a delegated objective so a runaway agent can't post huge tasks
# record_asset types whose value IS a host/URL, so it must pass the fail-closed
# target scope check.  Other types (param, path, endpoint, tech, email) carry no
# reachable host and use the best-effort check instead.
_HOST_LIKE_ASSET_TYPES = {"host", "hostname", "subdomain", "domain", "ip", "url", "vhost", "live_host"}


def _remaining_timeout(deps: AgentDeps, default: int) -> int:
    """Per-call timeout, capped by the run's remaining wall-clock budget."""
    if deps.deadline is None:
        return default
    remaining = int(deps.deadline - time.monotonic())
    return max(1, min(default, remaining))


def _precheck(deps: AgentDeps, tool: str) -> str | None:
    """Shared gate for every agent tool. Returns an error string if blocked."""
    if deps.past_deadline():
        return "STOP: time budget exhausted — finalize and summarize your findings now."
    if deps.ceiling_reached():
        return "STOP: tool-call ceiling reached — finalize and summarize your findings now."
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
            inst = cls()
        except Exception:
            continue
        if category and inst.category != category:
            continue
        binary = inst.binary or name
        present = shutil.which(binary) is not None
        if not present:
            continue
        lines.append(f"{name} [{inst.category}] → {binary}")
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
        step = f"[{language}] {code}"
        deps.exploit_plan.append(step)
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
    lines.extend(f"{k}: {v}" for k, v in headers.items())
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def _format_response(status_code: int, reason: str, headers: dict[str, str], body: str, truncated: bool) -> str:
    """Render a response as HTTP-wire-like evidence, ready for save_bug.response."""
    lines = [f"HTTP/1.1 {status_code} {reason}".rstrip()]
    lines.extend(f"{k}: {v}" for k, v in headers.items())
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

    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}

    # Pentester dry-run gate: a mutating request is a state change → record, don't send.
    if deps.agent.kind == AgentKind.PENTESTER and not deps.live_exploit_allowed and method not in _SAFE_METHODS:
        step = _format_request(method, url, hdrs, body)
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
        resp = requests.request(
            method,
            url,
            headers=hdrs or None,
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
        total = 0
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=4096):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_RESP_BYTES:
                break
        raw = b"".join(chunks)
        truncated = total > _MAX_RESP_BYTES
        text = raw[:_MAX_RESP_BYTES].decode(resp.encoding or "utf-8", "replace")
        resp_headers = dict(resp.headers)
        status_code = resp.status_code
        reason = resp.reason or ""
        final_url = resp.url
    finally:
        resp.close()

    deps.audit.record(
        "http_request",
        method=method,
        url=url,
        status=status_code,
        bytes=total,
        response=text,
    )
    return {
        "status_code": status_code,
        "url": final_url,
        "response_headers": resp_headers,
        "body": text,
        "truncated": truncated,
        "request": _format_request(method, url, hdrs, body),
        "response": _format_response(status_code, reason, resp_headers, text, truncated),
    }


# ── save_bug ──────────────────────────────────────────────────────────────────


def save_bug(
    deps: AgentDeps,
    title: str,
    severity: str = "info",
    target: str = "",
    affected_url: str = "",
    affected_param: str = "",
    vuln_class: list[str] | None = None,
    summary: str = "",
    reproduction_steps: list[str] | None = None,
    request: str = "",
    response: str = "",
    impact: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    oob_evidence: str = "",
    cvss_vector: str = "",
    cvss_score: float | None = None,
    confidence: str = "unknown",
) -> str:
    """Persist a confirmed bug (evidence of existence) for reporting/submission."""
    try:
        sev: Severity = _parse_severity(severity)
    except Exception:
        sev = Severity.INFO
    finding = AgentFinding(
        title=title,
        severity=sev,
        target=target,
        affected_url=affected_url,
        affected_param=affected_param,
        vuln_class=vuln_class or [],
        summary=summary,
        reproduction_steps=reproduction_steps or [],
        request=request,
        response=response,
        impact=impact,
        remediation=remediation,
        references=references or [],
        oob_evidence=oob_evidence,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        confidence=confidence,
        discovered_by=deps.agent.name,
    )
    deps.findings.append(finding)
    deps.audit.record("save_bug", title=title, severity=sev.value, target=target)
    return f"Saved bug #{len(deps.findings)}: {title} [{sev.value}]"


# ── record_poc ────────────────────────────────────────────────────────────────


def record_poc(
    deps: AgentDeps,
    finding_title: str,
    language: str,
    description: str,
    command: str = "",
    script: str = "",
    expected_indicator: str = "",
    executed: bool = False,
    verdict: str = "not_run",
    evidence: str = "",
) -> str:
    """Record a PoC artifact; writes the script to the agent artifact dir."""
    poc_id = f"agent-poc-{len(deps.pocs) + 1:03d}"
    script_path = ""
    if script.strip():
        ext = {"python": ".py", "bash": ".sh", "sh": ".sh"}.get(language.lower(), ".txt")
        path = deps.artifact_dir / f"{poc_id}{ext}"
        try:
            deps.artifact_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(script, encoding="utf-8")
            script_path = str(path)
        except OSError as exc:  # pragma: no cover - defensive
            log.warning("PoC write failed: %s", exc)
    poc = AgentPoc(
        id=poc_id,
        finding_title=finding_title,
        language=language,
        description=description,
        command=command,
        script_path=script_path,
        expected_indicator=expected_indicator,
        executed=executed,
        verdict=verdict,
        evidence=evidence,
    )
    deps.pocs.append(poc)
    deps.audit.record("record_poc", id=poc_id, finding=finding_title, verdict=verdict)
    return f"Recorded {poc_id} for '{finding_title}' (verdict: {verdict})"


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
    new = deps.oob_session.check()
    deps.audit.record("oob_check", new_interactions=len(new))
    return {"interactions": new, "count": len(new)}


# ── note / recall (agent scratchpad) ───────────────────────────────────────────


def _persist_note(deps: AgentDeps, entry: dict) -> None:
    """Best-effort append of a note to ``<agent>.notes.jsonl`` beside the action log.

    Gives the scratchpad the same post-hoc auditability as the action log without
    ever surfacing raw notes into the submission report.  Never raises — a
    notes-write failure must not crash an agent run.
    """
    path = deps.audit.path.parent / f"{deps.audit.path.stem}.notes.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
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
    text = _truncate(text)  # caps at _MAX_NOTE_LEN and appends a truncation marker
    seq = len(deps.notes) + 1
    entry = {"seq": seq, "tag": tag, "text": text, "ts": time.time()}
    deps.notes.append(entry)
    deps.audit.record("note", seq=seq, tag=tag, text=text)
    _persist_note(deps, entry)
    return f"Noted #{seq}" + (f" [{tag}]" if tag else "")


def recall(deps: AgentDeps, tag: str = "") -> str:
    """Return the scratchpad notes recorded so far, oldest first.

    Optionally filter by *tag*.  Read these back before summarizing so nothing
    discovered mid-run is lost when the context window rolls.
    """
    blocked = _precheck(deps, "recall")
    if blocked:
        return blocked

    tag = (tag or "").strip()
    entries = [n for n in deps.notes if not tag or n["tag"] == tag]
    deps.audit.record("recall", tag=tag, count=len(entries))
    if not entries:
        scope = f" tagged [{tag}]" if tag else ""
        return f"No notes recorded{scope} yet."

    lines = [f"#{n['seq']}" + (f" [{n['tag']}]" if n["tag"] else "") + f": {n['text']}" for n in entries]
    return "\n".join(lines)


# ── Multi-agent collaboration ───────────────────────────────────────────────────
#
# These tools share state between agents through the engagement blackboard and
# task queue.  They degrade gracefully to an informative message when the agent
# runs solo (no blackboard / queue injected), so the single-agent path is
# unaffected.  Every one routes through ``_precheck`` (ceiling / deadline /
# allow-deny), and every host-bearing value is scope-validated before it is
# published, so the blackboard cannot be used to smuggle an out-of-scope target
# to another agent.


def read_state(deps: AgentDeps, section: str = "") -> dict:
    """Read shared engagement state: assets, findings, credentials, and tasks.

    Network-free — it reads the in-process blackboard and task queue only.
    Credential *secrets* are never returned (only their shape: kind / username /
    host), so reading shared state cannot leak loot into an agent's context.
    """
    blocked = _precheck(deps, "read_state")
    if blocked:
        return {"error": blocked}

    want = (section or "").strip().lower()
    out: dict = {}
    if deps.blackboard is not None:
        counts = deps.blackboard.counts()
        out["counts"] = counts
        if want in ("", "assets"):
            out["assets"] = [
                {"type": a.type, "value": a.value, "source": a.source}
                for a in deps.blackboard.assets()[:_STATE_LIST_LIMIT]
            ]
        if want in ("", "findings"):
            out["findings"] = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "target": f.affected_url or f.target,
                    "by": f.discovered_by,
                }
                for f in deps.blackboard.findings()[:_STATE_LIST_LIMIT]
            ]
        if want in ("", "credentials"):
            out["credentials"] = [
                {"kind": c.kind, "username": c.username, "host": c.host}  # secret intentionally omitted
                for c in deps.blackboard.credentials()[:_STATE_LIST_LIMIT]
            ]
    if deps.task_queue is not None and want in ("", "tasks"):
        out["tasks"] = [
            {"id": t.id, "role": t.role, "objective": t.objective, "status": t.status.value, "claimed_by": t.claimed_by}
            for t in deps.task_queue.list()[:_STATE_LIST_LIMIT]
        ]
    deps.audit.record("read_state", section=want, counts=out.get("counts"))
    if not out:
        return {"note": "No shared engagement state available (running solo)."}
    return out


def share_finding(
    deps: AgentDeps,
    title: str,
    severity: str = "info",
    target: str = "",
    affected_url: str = "",
    summary: str = "",
    vuln_class: list[str] | None = None,
) -> str:
    """Publish a finding to the shared blackboard for other agents to build on.

    Distinct from :func:`save_bug`, which persists a full bug into *this*
    agent's report.  Use this to make a discovery visible mid-engagement.
    """
    blocked = _precheck(deps, "share_finding")
    if blocked:
        return blocked
    if deps.blackboard is None:
        return "No shared blackboard available (running solo) — use save_bug to record locally."

    try:
        severity_value: Severity = _parse_severity(severity)
    except Exception:
        severity_value = Severity.INFO
    finding = AgentFinding(
        title=title,
        severity=severity_value,
        target=target,
        affected_url=affected_url,
        summary=summary,
        vuln_class=vuln_class or [],
        discovered_by=deps.agent.name,
    )
    added = deps.blackboard.add_finding(finding)
    deps.audit.record("share_finding", title=title, severity=severity_value.value, added=added)
    return f"Shared finding '{title}'" + ("" if added else " (already known)")


def record_asset(deps: AgentDeps, asset_type: str, value: str) -> str:
    """Publish a discovered asset (host, URL, endpoint, parameter) to the blackboard.

    Host-bearing values are scope-validated first, so an out-of-scope asset is
    never propagated to other agents.
    """
    blocked = _precheck(deps, "record_asset")
    if blocked:
        return blocked
    if deps.blackboard is None:
        return "No shared blackboard available (running solo)."

    try:
        if asset_type.strip().lower() in _HOST_LIKE_ASSET_TYPES:
            deps.assert_target_in_scope(value)
        else:
            deps.assert_in_scope(value)
    except ScopeViolation as exc:
        deps.audit.record("record_asset", refused="scope", value=value)
        return str(exc)

    added = deps.blackboard.add_asset(asset_type, value, source=deps.agent.name)
    deps.audit.record("record_asset", asset_type=asset_type, value=value, added=added)
    return f"Recorded {asset_type} asset '{value}'" + ("" if added else " (already known)")


def record_credential(
    deps: AgentDeps,
    kind: str,
    secret: str,
    username: str = "",
    host: str = "",
) -> str:
    """Store a captured credential in the engagement-private loot store.

    The host is scope-validated.  Secrets stay in the blackboard for reuse
    during the run and are scrubbed from reports before they leave the process.
    """
    blocked = _precheck(deps, "record_credential")
    if blocked:
        return blocked
    if deps.blackboard is None:
        return "No shared blackboard available (running solo)."

    if host:
        try:
            deps.assert_target_in_scope(host)
        except ScopeViolation as exc:
            deps.audit.record("record_credential", refused="scope", host=host)
            return str(exc)

    from vuln_scanner.agents.blackboard import Credential

    credential = Credential(kind=kind, username=username, secret=secret, host=host, source=deps.agent.name)
    added = deps.blackboard.add_credential(credential)
    # The secret is never echoed back or audited — only the fact of capture.
    deps.audit.record("record_credential", kind=kind, username=username, host=host, added=added)
    return f"Recorded {kind} credential for '{username or '?'}@{host or '?'}'" + ("" if added else " (already known)")


def post_task(deps: AgentDeps, role: str, objective: str, target: str = "") -> str:
    """Delegate a task to a specialist role via the shared task queue.

    Privilege boundary: only an agent whose role may delegate (the lead) can
    post tasks; a specialist that calls this is refused.  The target role must
    be a known specialist, the target host is scope-validated, and the queue's
    own depth / count caps bound the delegation tree.
    """
    blocked = _precheck(deps, "post_task")
    if blocked:
        return blocked
    if deps.task_queue is None:
        return "No task queue available (running solo) — cannot delegate."
    if not deps.can_delegate:
        deps.audit.record("post_task", refused="not_delegator", role=deps.role)
        return "Refused: this role is not permitted to delegate work."

    from vuln_scanner.agents.roles import get_role, specialist_role_names

    target_role = (role or "").strip()
    if get_role(target_role) is None or target_role not in specialist_role_names():
        return f"Unknown specialist role '{target_role}'. Choose one of: {', '.join(specialist_role_names())}."

    if target:
        try:
            deps.assert_target_in_scope(target)
        except ScopeViolation as exc:
            deps.audit.record("post_task", refused="scope", target=target)
            return str(exc)

    objective = objective.strip()[:_MAX_OBJECTIVE_LEN]
    task = deps.task_queue.post(
        target_role, objective, target=target, created_by=deps.agent.name, parent=deps.current_task
    )
    if task is None:
        deps.audit.record("post_task", refused="cap", role=target_role)
        return "Refused: delegation budget reached (task count or depth cap)."
    deps.audit.record("post_task", task_id=task.id, role=target_role, objective=objective, target=target)
    return f"Posted {task.id} to '{target_role}': {objective}"
