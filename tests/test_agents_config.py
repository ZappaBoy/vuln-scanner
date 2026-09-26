"""M1 — agent models + config surface tests."""

from argparse import Namespace

from vuln_scanner.agents.models import (
    AgentConfig,
    AgentKind,
    AgentReport,
    AgentsConfig,
    AgentStatus,
    SandboxConfig,
)
from vuln_scanner.config.loader import build_arg_parser, load_config


def _args(**kwargs) -> Namespace:
    base = build_arg_parser().parse_args([])
    for k, v in kwargs.items():
        setattr(base, k, v)
    return base


# ── Models ────────────────────────────────────────────────────────────────────


def test_agent_config_defaults():
    a = AgentConfig(name="hunter", kind=AgentKind.BUG_BOUNTY)
    assert a.enabled is True
    assert a.allow_exploitation is False
    assert a.require_approval is False
    assert a.timeout == 600
    assert a.max_tool_calls == 40


def test_agents_config_active_filter():
    cfg = AgentsConfig(
        agents=[
            AgentConfig(name="a", kind=AgentKind.BUG_BOUNTY, enabled=True),
            AgentConfig(name="b", kind=AgentKind.PENTESTER, enabled=False),
        ]
    )
    active = cfg.active_agents()
    assert [a.name for a in active] == ["a"]


def test_sandbox_defaults():
    s = SandboxConfig()
    assert s.max_procs == 64  # fork-bomb guard present
    assert s.network == "lab"


def test_agent_report_roundtrip():
    r = AgentReport(agent_name="hunter", kind=AgentKind.BUG_BOUNTY, status=AgentStatus.TIMED_OUT)
    dumped = r.model_dump()
    assert dumped["status"] == "timed_out"
    assert dumped["findings"] == []


# ── Config wiring ──────────────────────────────────────────────────────────────


def test_agents_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    config = load_config(_args())
    assert config.agents.enabled is False
    assert config.agents.scope_enforcement is True


def test_agents_env_toggle(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VS_AGENTS_ENABLED", "true")
    config = load_config(_args())
    assert config.agents.enabled is True


def test_agents_scope_enforcement_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VS_AGENTS_SCOPE_ENFORCEMENT", "false")
    config = load_config(_args())
    assert config.agents.scope_enforcement is False


def test_agents_toml_and_build(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        """
[agents]
enabled = true

[[agents.agents]]
name = "hunter"
kind = "bug_bounty"
timeout = 300

[[agents.agents]]
name = "operator"
kind = "pentester"
allow_exploitation = true
require_approval = true

[agents.sandbox]
memory_mb = 256
max_procs = 32
"""
    )
    config = load_config(_args(config=str(cfg)))
    assert config.agents.enabled is True

    typed = config.build_agents_config()
    assert isinstance(typed, AgentsConfig)
    assert typed.enabled is True
    assert len(typed.agents) == 2
    hunter, operator = typed.agents
    assert hunter.kind == AgentKind.BUG_BOUNTY
    assert hunter.timeout == 300
    assert operator.kind == AgentKind.PENTESTER
    assert operator.allow_exploitation is True
    assert operator.require_approval is True
    assert typed.sandbox.memory_mb == 256
    assert typed.sandbox.max_procs == 32


def test_build_agents_config_empty_defaults(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    config = load_config(_args())
    typed = config.build_agents_config()
    assert typed.enabled is False
    assert typed.agents == []
    assert typed.scope_enforcement is True
