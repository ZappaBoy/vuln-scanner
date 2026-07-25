"""M3 — agent tool implementations + OOB parsers."""

from pathlib import Path

from vuln_scanner.agents.agent_tools import (
    list_tools,
    oob_get_callback,
    record_poc,
    run_code,
    run_tool,
    save_bug,
)
from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.deps import AgentDeps
from vuln_scanner.agents.models import AgentConfig, AgentKind, AgentsConfig
from vuln_scanner.agents.oob import parse_callback_domain, parse_interaction
from vuln_scanner.scope import ScopeValidator


def _deps(
    tmp_path,
    *,
    kind=AgentKind.BUG_BOUNTY,
    include=None,
    allowlist=None,
    live_exploit=False,
    max_tool_calls=40,
    deadline=None,
) -> AgentDeps:
    scope = ScopeValidator(include=include or [], exclude=[], strict=False)
    agent = AgentConfig(name="hunter", kind=kind, max_tool_calls=max_tool_calls)
    return AgentDeps(
        agent=agent,
        agents_cfg=AgentsConfig(),
        scope=scope,
        audit=ActionLog(tmp_path, "hunter"),
        artifact_dir=Path(tmp_path),
        allowlist=set(allowlist or []),
        live_exploit_allowed=live_exploit,
        deadline=deadline,
    )


# ── precheck / ceilings ───────────────────────────────────────────────────────


def test_run_tool_unknown_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "no_such_tool", ["-x"], target="t.lab")
    assert "Unknown tool" in out["error"]


def test_ceiling_blocks_further_calls(tmp_path):
    deps = _deps(tmp_path, max_tool_calls=0)
    out = run_tool(deps, "nmap", ["-sV"], target="t.lab")
    assert "ceiling" in out["error"].lower()


def test_denied_tool(tmp_path):
    deps = _deps(tmp_path)
    deps.agent.denied_tools = ["run_code"]
    out = run_code(deps, "python", "print(1)")
    assert "denied" in out["error"].lower()


# ── run_tool guards ───────────────────────────────────────────────────────────


def test_run_tool_refuses_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, include=["t.lab"])
    out = run_tool(deps, "nmap", ["-sV", "evil.example.com"], target="evil.example.com")
    assert "out of scope" in out["error"].lower()


def test_run_tool_refuses_denylisted_args(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "nmap", ["-oN", "/etc/shadow", "t.lab"], target="t.lab")
    assert "Refused" in out["error"]


def test_run_tool_refuses_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "nmap", ["-sV", "t.lab"], target="t.lab")
    assert "container" in out["error"].lower()


# ── run_code dry-run gate ─────────────────────────────────────────────────────


def test_pentester_dry_run_records_plan(tmp_path):
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, live_exploit=False)
    out = run_code(deps, "python", "print('exploit attempt')")
    assert out["executed"] is False
    assert deps.exploit_plan and "exploit attempt" in deps.exploit_plan[0]


def test_pentester_live_executes(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, live_exploit=True)
    out = run_code(deps, "python", "print('poc-live-99')")
    assert out["executed"] is True
    assert "poc-live-99" in out["stdout"]


def test_bug_bounty_executes_benign_code(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path)
    out = run_code(deps, "python", "print('bb-proof-7')")
    assert out["executed"] is True
    assert "bb-proof-7" in out["stdout"]


def test_run_code_scope_check_on_host_literal(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, include=["t.lab"])
    out = run_code(deps, "python", "import urllib.request; urllib.request.urlopen('http://evil.example.com')")
    assert "out of scope" in out["error"].lower()


# ── save_bug / record_poc ─────────────────────────────────────────────────────


def test_save_bug_appends(tmp_path):
    deps = _deps(tmp_path)
    msg = save_bug(
        deps,
        title="Reflected XSS in q param",
        severity="high",
        target="t.lab",
        affected_param="q",
        reproduction_steps=["visit /?q=<script>", "observe alert"],
    )
    assert "Saved bug" in msg
    assert len(deps.findings) == 1
    f = deps.findings[0]
    assert f.severity.value == "high"
    assert f.discovered_by == "hunter"
    assert f.affected_param == "q"


def test_record_poc_writes_script(tmp_path):
    deps = _deps(tmp_path)
    msg = record_poc(
        deps,
        finding_title="SSRF",
        language="python",
        description="fetch internal metadata",
        script="print('poc')",
        verdict="confirmed",
    )
    assert "agent-poc-001" in msg
    assert len(deps.pocs) == 1
    assert Path(deps.pocs[0].script_path).exists()


# ── list_tools ────────────────────────────────────────────────────────────────


def test_list_tools_returns_string(tmp_path):
    deps = _deps(tmp_path)
    out = list_tools(deps)
    assert isinstance(out, str)


# ── OOB ───────────────────────────────────────────────────────────────────────


def test_oob_unavailable_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    deps = _deps(tmp_path)
    out = oob_get_callback(deps)
    assert "container" in out.lower()


def test_parse_callback_domain():
    text = "[INF] Listing 1 payload for OOB Testing\nc8r1abcdefgh12345678ij.oast.pro"
    assert parse_callback_domain(text) == "c8r1abcdefgh12345678ij.oast.pro"


def test_parse_interaction_valid():
    line = '{"protocol":"dns","remote-address":"1.2.3.4","raw-request":"q","timestamp":"t"}'
    rec = parse_interaction(line)
    assert rec is not None
    assert rec["protocol"] == "dns"
    assert rec["source"] == "1.2.3.4"


def test_parse_interaction_ignores_noise():
    assert parse_interaction("not json") is None
    assert parse_interaction('{"no":"protocol"}') is None
