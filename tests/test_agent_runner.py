"""M4 — AgentOrchestrator lifecycle: gating, sequential order, timeout, crash."""

import asyncio
from pathlib import Path

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from vuln_scanner.agents.models import (
    AgentConfig,
    AgentKind,
    AgentReport,
    AgentsConfig,
    AgentStatus,
)
from vuln_scanner.agents.runner import AgentOrchestrator, build_allowlist_hosts
from vuln_scanner.config.models import AppLLMConfig
from vuln_scanner.model import Assessment
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools.enums import ScanMode


def _llm():
    from vuln_scanner.config.models import AppConfig

    cfg = AppConfig(llm=AppLLMConfig(enabled=True, api_key="k", model="gpt-x"))
    return cfg.build_llm_config()


def _orch(tmp_path, agents, *, enabled=True, model=None, mode=ScanMode.ACTIVE):
    cfg = AgentsConfig(enabled=enabled, agents=agents)
    return AgentOrchestrator(
        agents_cfg=cfg,
        llm_config=_llm(),
        scope=ScopeValidator(include=["t.lab"], exclude=[], strict=False),
        run_dir=Path(tmp_path),
        mode=mode,
        allowlist_hosts={"t.lab"},
        model=model,
    )


def _assessment():
    return Assessment.from_results([])


# ── Allowlist helper ──────────────────────────────────────────────────────────


def test_build_allowlist_hosts():
    hosts = build_allowlist_hosts(["https://app.t.lab/x", "10.0.0.5", "t.lab:443"])
    assert "app.t.lab" in hosts
    assert "10.0.0.5" in hosts
    assert "t.lab" in hosts


# ── Gating ────────────────────────────────────────────────────────────────────


def test_disabled_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    orch = _orch(tmp_path, [AgentConfig(name="a", kind=AgentKind.BUG_BOUNTY)], enabled=False, model=TestModel())
    assert orch.run(_assessment()) == []


def test_not_in_container_returns_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    orch = _orch(tmp_path, [AgentConfig(name="a", kind=AgentKind.BUG_BOUNTY)], model=TestModel())
    assert orch.run(_assessment()) == []


def test_no_active_agents_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    orch = _orch(tmp_path, [AgentConfig(name="a", kind=AgentKind.BUG_BOUNTY, enabled=False)], model=TestModel())
    assert orch.run(_assessment()) == []


# ── Happy path with TestModel ─────────────────────────────────────────────────


def test_runs_agent_and_produces_report(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    orch = _orch(tmp_path, [AgentConfig(name="hunter", kind=AgentKind.BUG_BOUNTY)], model=TestModel())
    reports = orch.run(_assessment())
    assert len(reports) == 1
    r = reports[0]
    assert isinstance(r, AgentReport)
    assert r.agent_name == "hunter"
    assert r.status == AgentStatus.COMPLETED
    assert r.summary  # TestModel returns some text
    # audit log written
    assert Path(r.action_log_path).exists()


def test_agents_run_sequentially_in_order(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    agents = [
        AgentConfig(name="first", kind=AgentKind.BUG_BOUNTY),
        AgentConfig(name="second", kind=AgentKind.PENTESTER),
    ]
    orch = _orch(tmp_path, agents, model=TestModel())
    reports = orch.run(_assessment())
    assert [r.agent_name for r in reports] == ["first", "second"]


# ── Timeout → summarize ───────────────────────────────────────────────────────


def _hang_or_summarize(messages, info: AgentInfo) -> ModelResponse:
    # The summarize call uses a distinct system prompt; answer it fast.
    text = " ".join(str(getattr(p, "content", "")) for m in messages for p in m.parts)
    if "Summarize the security testing" in text:
        return ModelResponse(parts=[TextPart("Summary: nothing conclusive.")])
    # Main run: block so wait_for cancels it.
    import time as _t

    _t.sleep(3)
    return ModelResponse(parts=[TextPart("late")])


async def _slow(messages, info: AgentInfo) -> ModelResponse:
    text = " ".join(str(getattr(p, "content", "")) for m in messages for p in m.parts)
    if "Summarize the security testing" in text:
        return ModelResponse(parts=[TextPart("Summary: partial results only.")])
    await asyncio.sleep(3)
    return ModelResponse(parts=[TextPart("late")])


def test_timeout_triggers_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    agent = AgentConfig(name="slowpoke", kind=AgentKind.BUG_BOUNTY, timeout=1)
    orch = _orch(tmp_path, [agent], model=FunctionModel(_slow))
    reports = orch.run(_assessment())
    assert len(reports) == 1
    assert reports[0].status == AgentStatus.TIMED_OUT
    assert "partial results" in reports[0].summary


# ── Crash isolation ───────────────────────────────────────────────────────────


def test_one_agent_crash_does_not_kill_phase(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")

    def _boom(messages, info: AgentInfo) -> ModelResponse:
        raise RuntimeError("model exploded")

    agents = [
        AgentConfig(name="crasher", kind=AgentKind.BUG_BOUNTY),
        AgentConfig(name="survivor", kind=AgentKind.BUG_BOUNTY),
    ]
    # crasher uses a broken model; survivor uses TestModel — but the orchestrator
    # shares one model, so make the shared model crash and assert isolation of the
    # crashing agent while the phase still returns a report per agent.
    orch = _orch(tmp_path, agents, model=FunctionModel(_boom))
    reports = orch.run(_assessment())
    assert len(reports) == 2
    assert all(r.status == AgentStatus.ERROR for r in reports)
    assert "exploded" in reports[0].summary
