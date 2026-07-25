"""M6 — Agent Operations section in HTML/Markdown/JSON reports."""

import json
from pathlib import Path

from vuln_scanner.agents.models import AgentFinding, AgentKind, AgentPoc, AgentReport, AgentStatus
from vuln_scanner.model import Assessment
from vuln_scanner.reports.html import HTMLReporter
from vuln_scanner.reports.json_reporter import JSONReporter
from vuln_scanner.reports.markdown import MarkdownReporter
from vuln_scanner.tools.enums import Severity


def _report() -> AgentReport:
    return AgentReport(
        agent_name="hunter",
        kind=AgentKind.BUG_BOUNTY,
        status=AgentStatus.COMPLETED,
        summary="Found a reflected XSS and an SSRF.",
        actions_taken=7,
        tokens_used=1234,
        duration=42.0,
        action_log_path="/runs/agent_logs/hunter.jsonl",
        findings=[
            AgentFinding(
                title="Reflected XSS in q",
                severity=Severity.HIGH,
                affected_url="https://app.t.lab/s?q=1",
                vuln_class=["CWE-79"],
                verified=True,
            )
        ],
        pocs=[AgentPoc(id="agent-poc-001", language="python", description="xss poc", verdict="confirmed")],
    )


def _pentester_report() -> AgentReport:
    return AgentReport(
        agent_name="operator",
        kind=AgentKind.PENTESTER,
        status=AgentStatus.TIMED_OUT,
        summary="Dry-run plan produced.",
        exploit_plan=["[python] import requests; requests.get('http://t.lab/admin')"],
    )


def _assessment() -> Assessment:
    return Assessment.from_results([], agent_reports=[_report(), _pentester_report()])


def test_markdown_has_agent_section(tmp_path):
    out = Path(tmp_path) / "r.md"
    MarkdownReporter().generate(_assessment(), out)
    text = out.read_text()
    assert "## Agent Operations" in text
    assert "hunter (bug_bounty)" in text
    assert "Reflected XSS in q" in text
    assert "CWE-79" in text
    assert "agent-poc-001" in text
    assert "Dry-run exploit plan" in text
    assert "/admin" in text


def test_html_has_agent_section(tmp_path):
    out = Path(tmp_path) / "r.html"
    HTMLReporter().generate(_assessment(), out)
    html = out.read_text()
    assert "Agent Operations" in html
    assert "hunter" in html
    assert "Reflected XSS in q" in html
    assert "Dry-run exploit plan" in html


def test_json_includes_agent_reports(tmp_path):
    out = Path(tmp_path) / "r.json"
    JSONReporter().generate(_assessment(), out)
    data = json.loads(out.read_text())
    assert "agent_reports" in data
    assert len(data["agent_reports"]) == 2
    assert data["agent_reports"][0]["agent_name"] == "hunter"
    assert data["agent_reports"][0]["findings"][0]["vuln_class"] == ["CWE-79"]


def test_no_agent_section_when_empty(tmp_path):
    out = Path(tmp_path) / "r.md"
    MarkdownReporter().generate(Assessment.from_results([]), out)
    assert "Agent Operations" not in out.read_text()
