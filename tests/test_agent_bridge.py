"""#2/#4 — bridging agent findings into the findings pipeline + stats."""

from argparse import Namespace

from vuln_scanner.agents.bridge import agent_reports_to_results, bridge_into_assessment
from vuln_scanner.agents.models import AgentFinding, AgentKind, AgentReport
from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.model import Assessment
from vuln_scanner.tools.enums import Confidence, Severity


def _args(**kwargs) -> Namespace:
    base = build_arg_parser().parse_args([])
    for k, v in kwargs.items():
        setattr(base, k, v)
    return base


def _report() -> AgentReport:
    return AgentReport(
        agent_name="hunter",
        kind=AgentKind.BUG_BOUNTY,
        findings=[
            AgentFinding(
                title="SQLi in id param",
                severity=Severity.CRITICAL,
                affected_url="https://app.t.lab/item?id=1",
                vuln_class=["CWE-89"],
                summary="Boolean-based blind SQLi.",
                confidence="high",
                verified=True,
                discovered_by="hunter",
            )
        ],
    )


def test_conversion_maps_fields():
    results = agent_reports_to_results([_report()])
    assert len(results) == 1
    r = results[0]
    assert r.tool == "agent:hunter"
    f = r.findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.cwe == ["CWE-89"]
    assert f.confidence == Confidence.HIGH
    assert f.target == "https://app.t.lab/item?id=1"
    assert f.raw["verified"] is True


def test_bridge_counts_in_stats():
    assessment = Assessment.from_results([], agent_reports=[_report()])
    assert assessment.stats.by_severity.get("critical", 0) == 0  # before bridge
    n = bridge_into_assessment(assessment)
    assert n == 1
    assert assessment.stats.by_severity["critical"] == 1
    assert assessment.stats.total_findings == 1
    assert "agent:hunter" in assessment.stats.by_tool


def test_bridge_is_idempotent():
    assessment = Assessment.from_results([], agent_reports=[_report()])
    assert bridge_into_assessment(assessment) == 1
    assert bridge_into_assessment(assessment) == 0  # second call is a no-op
    assert assessment.stats.total_findings == 1


def test_bridge_no_agent_findings():
    assessment = Assessment.from_results([])
    assert bridge_into_assessment(assessment) == 0


def test_refresh_stats_preserves_chaining_fields():
    assessment = Assessment.from_results(
        [], agent_reports=[_report()], assets_by_type={"url": 5}, waves_run=3
    )
    bridge_into_assessment(assessment)
    assert assessment.stats.assets_by_type == {"url": 5}
    assert assessment.stats.waves_run == 3


# ── #11 CLI flags ─────────────────────────────────────────────────────────────


def test_cli_agents_enable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    config = load_config(_args(agents=True))
    assert config.agents.enabled is True


def test_cli_no_agents_wins(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    config = load_config(_args(agents=True, no_agents=True))
    assert config.agents.enabled is False


def test_cli_no_agents_overrides_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VS_AGENTS_ENABLED", "true")
    config = load_config(_args(no_agents=True))
    assert config.agents.enabled is False
