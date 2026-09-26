"""Multi-agent collaboration tools: shared state, publishing, and delegation.

Covers the security-relevant behavior: scope validation on every published
host, credential secrets never leaking into read_state or the audit log, and
the delegation privilege boundary (only a delegating role may post tasks).
"""

import json
from pathlib import Path

from vuln_scanner.agents.agent_tools import (
    post_task,
    read_state,
    record_asset,
    record_credential,
    share_finding,
)
from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.blackboard import Credential, EngagementState
from vuln_scanner.agents.deps import AgentDeps
from vuln_scanner.agents.models import AgentConfig, AgentKind, AgentsConfig
from vuln_scanner.agents.tasks import TaskQueue
from vuln_scanner.scope import ScopeValidator


def _deps(
    tmp_path,
    *,
    blackboard=None,
    task_queue=None,
    role="",
    can_delegate=False,
    include=("t.lab",),
    max_tool_calls=40,
) -> AgentDeps:
    scope = ScopeValidator(include=list(include), exclude=[], strict=False)
    agent = AgentConfig(name=role or "agent", kind=AgentKind.BUG_BOUNTY, max_tool_calls=max_tool_calls)
    return AgentDeps(
        agent=agent,
        agents_cfg=AgentsConfig(),
        scope=scope,
        audit=ActionLog(tmp_path, role or "agent"),
        artifact_dir=Path(tmp_path),
        allowlist={"t.lab"},
        blackboard=blackboard,
        task_queue=task_queue,
        role=role,
        can_delegate=can_delegate,
    )


# ── Solo degradation ────────────────────────────────────────────────────────────


def test_tools_degrade_gracefully_when_solo(tmp_path):
    deps = _deps(tmp_path)
    assert "solo" in read_state(deps).get("note", "").lower()
    assert "solo" in share_finding(deps, "x").lower()
    assert "solo" in record_asset(deps, "url", "https://t.lab/a").lower()
    assert "solo" in post_task(deps, "web", "do it").lower()


# ── read_state ────────────────────────────────────────────────────────────────


def test_read_state_returns_shared_view_without_secrets(tmp_path):
    board = EngagementState()
    board.add_asset("url", "https://t.lab/a", source="recon")
    board.add_credential(Credential(kind="password", username="admin", secret="HUNTER2", host="t.lab"))
    deps = _deps(tmp_path, blackboard=board)

    out = read_state(deps)
    assert out["counts"]["assets"] == 1
    assert out["assets"][0]["value"] == "https://t.lab/a"
    # Credential is visible in shape but the secret must not be returned.
    assert out["credentials"][0]["username"] == "admin"
    assert "HUNTER2" not in json.dumps(out)


# ── record_asset scope enforcement ───────────────────────────────────────────────


def test_record_asset_rejects_out_of_scope(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board)
    msg = record_asset(deps, "subdomain", "evil.example.com")
    assert "out of scope" in msg.lower()
    assert board.counts()["assets"] == 0


def test_record_asset_accepts_in_scope_and_dedups(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board)
    assert "Recorded" in record_asset(deps, "url", "https://t.lab/a")
    assert "already known" in record_asset(deps, "url", "https://t.lab/a")
    assert board.counts()["assets"] == 1


# ── record_credential ────────────────────────────────────────────────────────────


def test_record_credential_rejects_out_of_scope_host(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board)
    msg = record_credential(deps, kind="password", secret="p", username="a", host="evil.example.com")
    assert "out of scope" in msg.lower()
    assert board.counts()["credentials"] == 0


def test_record_credential_never_writes_secret_to_audit_log(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board)
    record_credential(deps, kind="password", secret="SUPERSECRET", username="admin", host="t.lab")
    assert board.counts()["credentials"] == 1
    audit_text = Path(deps.audit.path).read_text()
    assert "SUPERSECRET" not in audit_text


# ── share_finding ────────────────────────────────────────────────────────────────


def test_share_finding_publishes_and_dedups(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board)
    assert "Shared finding" in share_finding(deps, "SQLi", severity="high", affected_url="https://t.lab/q")
    assert "already known" in share_finding(deps, "SQLi", severity="high", affected_url="https://t.lab/q")
    assert board.counts()["findings"] == 1


# ── post_task delegation boundary ─────────────────────────────────────────────────


def test_post_task_refused_for_non_delegator(tmp_path):
    queue = TaskQueue()
    deps = _deps(tmp_path, task_queue=queue, role="web", can_delegate=False)
    msg = post_task(deps, "network", "enumerate services")
    assert "not permitted to delegate" in msg.lower()
    assert queue.pending_count() == 0


def test_post_task_rejects_unknown_role(tmp_path):
    queue = TaskQueue()
    deps = _deps(tmp_path, task_queue=queue, role="lead", can_delegate=True)
    msg = post_task(deps, "wizard", "cast a spell")
    assert "unknown specialist role" in msg.lower()


def test_post_task_scope_checks_target(tmp_path):
    queue = TaskQueue()
    deps = _deps(tmp_path, task_queue=queue, role="lead", can_delegate=True)
    msg = post_task(deps, "web", "test it", target="https://evil.example.com")
    assert "out of scope" in msg.lower()
    assert queue.pending_count() == 0


def test_post_task_success_enqueues(tmp_path):
    queue = TaskQueue()
    deps = _deps(tmp_path, task_queue=queue, role="lead", can_delegate=True)
    msg = post_task(deps, "web", "test /login", target="https://t.lab")
    assert "Posted" in msg
    assert queue.pending_count("web") == 1


def test_post_task_respects_queue_cap(tmp_path):
    queue = TaskQueue(max_tasks=1)
    deps = _deps(tmp_path, task_queue=queue, role="lead", can_delegate=True)
    assert "Posted" in post_task(deps, "web", "one", target="https://t.lab")
    assert "budget reached" in post_task(deps, "web", "two", target="https://t.lab").lower()


# ── Scope-bypass regression (red-team audit #1): unparseable / IPv6 / homoglyph ──


def test_record_asset_host_like_rejects_bypass_vectors(tmp_path):
    """Host-like assets must fail closed for hosts extract_hosts cannot parse."""
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board, include=("t.lab",))
    for bad in ["2001:db8::1", "[2001:db8::1]:443", "internal-admin", "localhost", "evil。com"]:
        msg = record_asset(deps, "host", bad)
        assert "scope" in msg.lower() or "refused" in msg.lower(), f"{bad!r} was not rejected: {msg}"
    assert board.counts()["assets"] == 0


def test_record_asset_data_types_still_allow_hostless_values(tmp_path):
    """A param/endpoint value has no reachable host and must not be scope-rejected."""
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board, include=("t.lab",))
    assert "Recorded" in record_asset(deps, "param", "redirect_uri")
    assert "Recorded" in record_asset(deps, "endpoint", "/api/v1/users")


def test_record_asset_host_like_accepts_in_scope(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board, include=("t.lab",))
    assert "Recorded" in record_asset(deps, "host", "t.lab")


def test_record_credential_rejects_ipv6_out_of_scope(tmp_path):
    board = EngagementState()
    deps = _deps(tmp_path, blackboard=board, include=("t.lab",))
    msg = record_credential(deps, kind="password", secret="p", username="a", host="2001:db8::1")
    assert "scope" in msg.lower() or "refused" in msg.lower()
    assert board.counts()["credentials"] == 0


def test_post_task_rejects_ipv6_out_of_scope_target(tmp_path):
    queue = TaskQueue()
    deps = _deps(tmp_path, task_queue=queue, role="lead", can_delegate=True, include=("t.lab",))
    msg = post_task(deps, "network", "enum", target="[2001:db8::1]:443")
    assert "scope" in msg.lower() or "refused" in msg.lower()
    assert queue.pending_count() == 0
