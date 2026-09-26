"""Supervisor: lead→specialist delegation, concurrency caps, per-host locking."""

from pathlib import Path

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from vuln_scanner.agents.models import AgentsConfig, OrchestrationConfig
from vuln_scanner.agents.runner import AgentOrchestrator
from vuln_scanner.agents.supervisor import Supervisor
from vuln_scanner.config.models import AppConfig, AppLLMConfig
from vuln_scanner.model import Assessment
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools.enums import ScanMode


def _llm():
    return AppConfig(llm=AppLLMConfig(enabled=True, api_key="k", model="gpt-x")).build_llm_config()


def _orch(tmp_path, orchestration: OrchestrationConfig, model, *, allowlist=("t.lab",), include=("t.lab",)):
    cfg = AgentsConfig(enabled=True, orchestration=orchestration)
    return AgentOrchestrator(
        agents_cfg=cfg,
        llm_config=_llm(),
        scope=ScopeValidator(include=list(include), exclude=[], strict=False),
        run_dir=Path(tmp_path),
        mode=ScanMode.ACTIVE,
        allowlist_hosts=set(allowlist),
        model=model,
    )


def _messages_text(messages) -> str:
    return " ".join(str(getattr(p, "content", "")) for m in messages for p in m.parts)


def _has_tool_return(messages) -> bool:
    return any(getattr(p, "part_kind", "") == "tool-return" for m in messages for p in m.parts)


def _lead_posts(*specs):
    """Build a FunctionModel driver: the lead posts the given tasks, each
    specialist shares one finding then finishes."""

    def _driver(messages, info: AgentInfo) -> ModelResponse:
        text = _messages_text(messages)
        is_lead = "You are the lead" in text
        if is_lead:
            if _has_tool_return(messages):
                return ModelResponse(parts=[TextPart("planned")])
            return ModelResponse(
                parts=[
                    ToolCallPart(tool_name="post_task", args={"role": role, "objective": obj, "target": target})
                    for (role, obj, target) in specs
                ]
            )
        # specialist
        if _has_tool_return(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(
            parts=[ToolCallPart(tool_name="share_finding", args={"title": "bug " + text[-8:], "severity": "high"})]
        )

    return FunctionModel(_driver)


def test_lead_delegates_and_specialists_run(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    model = _lead_posts(
        ("web", "test /login", "https://t.lab/login"),
        ("network", "enumerate services", "t.lab"),
    )
    orch = _orch(tmp_path, OrchestrationConfig(enabled=True, max_rounds=1, max_concurrent=2), model)
    reports = orch.run(Assessment.from_results([]))

    names = [r.agent_name for r in reports]
    assert names[0] == "lead"
    assert {"web", "network"} <= set(names)
    # Each specialist published a finding to the shared blackboard.
    specialist_reports = [r for r in reports if r.agent_name in ("web", "network")]
    assert len(specialist_reports) == 2


def test_lead_posting_nothing_stops_early(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")

    def _driver(messages, info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart("nothing to do")])

    orch = _orch(tmp_path, OrchestrationConfig(enabled=True, max_rounds=3), FunctionModel(_driver))
    reports = orch.run(Assessment.from_results([]))
    assert [r.agent_name for r in reports] == ["lead"]


def test_max_agent_runs_caps_specialists(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    model = _lead_posts(
        ("web", "a", "https://t.lab/a"),
        ("web", "b", "https://t.lab/b"),
        ("web", "c", "https://t.lab/c"),
    )
    orch = _orch(
        tmp_path,
        OrchestrationConfig(enabled=True, max_rounds=1, max_concurrent=3, max_agent_runs=2),
        model,
    )
    reports = orch.run(Assessment.from_results([]))
    specialists = [r for r in reports if r.agent_name == "web"]
    assert len(specialists) == 2  # third task never runs — run budget exhausted


# ── Per-host lock mechanism ──────────────────────────────────────────────────


def test_host_lock_identity():
    sup = Supervisor.__new__(Supervisor)  # no LLM needed to test the lock map
    sup._host_locks = {}
    a1 = sup._host_lock("https://t.lab/x")
    a2 = sup._host_lock("http://t.lab/y")  # same host → same lock
    b = sup._host_lock("https://other.lab/z")
    assert a1 is a2
    assert a1 is not b
    # Hostless target → a fresh, uncontended lock each time.
    assert sup._host_lock("") is not sup._host_lock("")


def _concurrency_probe_driver(active, targets):
    """Lead posts two web tasks; each specialist increments a live counter,
    makes a tool call (an await point where the loop can switch coroutines),
    then decrements — so an unlocked interleave would push max above 1."""

    def _driver(messages, info: AgentInfo) -> ModelResponse:
        text = _messages_text(messages)
        if "You are the lead" in text:
            if _has_tool_return(messages):
                return ModelResponse(parts=[TextPart("planned")])
            return ModelResponse(
                parts=[
                    ToolCallPart(tool_name="post_task", args={"role": "web", "objective": "x", "target": t})
                    for t in targets
                ]
            )
        if _has_tool_return(messages):
            active["n"] -= 1
            return ModelResponse(parts=[TextPart("done")])
        active["n"] += 1
        active["max"] = max(active["max"], active["n"])
        return ModelResponse(parts=[ToolCallPart(tool_name="note", args={"text": "probe"})])

    return FunctionModel(_driver)


def test_same_host_tasks_are_serialized(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    active = {"n": 0, "max": 0}
    model = _concurrency_probe_driver(active, ["https://t.lab/a", "https://t.lab/b"])
    orch = _orch(tmp_path, OrchestrationConfig(enabled=True, max_rounds=1, max_concurrent=4), model)
    orch.run(Assessment.from_results([]))
    assert active["max"] == 1  # same host t.lab → per-host lock forbids overlap


def test_different_host_tasks_run_concurrently(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    active = {"n": 0, "max": 0}
    model = _concurrency_probe_driver(active, ["https://a.t.lab/x", "https://b.t.lab/y"])
    orch = _orch(
        tmp_path,
        OrchestrationConfig(enabled=True, max_rounds=1, max_concurrent=4),
        model,
        allowlist=("a.t.lab", "b.t.lab"),
    )
    orch.run(Assessment.from_results([]))
    assert active["max"] == 2  # distinct hosts → allowed to overlap
