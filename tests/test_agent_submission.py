"""M5 — prompts override precedence + submission rendering."""

from pathlib import Path

from vuln_scanner.agents.models import (
    AgentConfig,
    AgentFinding,
    AgentKind,
    AgentReport,
    SubmissionConfig,
)
from vuln_scanner.agents.prompts import (
    BUG_BOUNTY_SYSTEM,
    PENTESTER_SYSTEM,
    system_prompt_for,
)
from vuln_scanner.agents.submission import (
    DEFAULT_SUBMISSION_TEMPLATE,
    render_submission,
    write_submissions,
)
from vuln_scanner.tools.enums import Severity

# ── Prompt precedence ─────────────────────────────────────────────────────────


def test_default_prompt_by_kind():
    assert system_prompt_for(AgentKind.BUG_BOUNTY) == BUG_BOUNTY_SYSTEM
    assert system_prompt_for(AgentKind.PENTESTER) == PENTESTER_SYSTEM
    assert "PROVE a vulnerability EXISTS" in BUG_BOUNTY_SYSTEM
    assert "DRY-RUN" in PENTESTER_SYSTEM


def test_config_prompt_override_wins():
    agent = AgentConfig(name="x", kind=AgentKind.BUG_BOUNTY, system_prompt="CUSTOM PROMPT")
    effective = agent.system_prompt or system_prompt_for(agent.kind)
    assert effective == "CUSTOM PROMPT"


def test_empty_prompt_falls_back():
    agent = AgentConfig(name="x", kind=AgentKind.PENTESTER)
    effective = agent.system_prompt or system_prompt_for(agent.kind)
    assert effective == PENTESTER_SYSTEM


# ── Submission rendering ──────────────────────────────────────────────────────


def _finding() -> AgentFinding:
    return AgentFinding(
        title="Reflected XSS in search",
        severity=Severity.HIGH,
        target="https://app.t.lab",
        affected_url="https://app.t.lab/search?q=1",
        affected_param="q",
        vuln_class=["CWE-79"],
        summary="User input reflected without encoding.",
        reproduction_steps=["Open /search?q=<script>alert(1)</script>", "Observe alert"],
        request="GET /search?q=<script> HTTP/1.1",
        response="200 OK ... <script>",
        impact="Session theft.",
        remediation="Context-encode output.",
        references=["https://owasp.org/xss"],
        cvss_score=7.4,
        confidence="high",
        discovered_by="hunter",
    )


def test_render_default_template():
    md = render_submission(_finding())
    assert "# Reflected XSS in search" in md
    assert "CWE-79" in md
    assert "1. Open /search" in md
    assert "app.t.lab/search" in md
    assert "7.4" in md


def test_render_custom_template():
    md = render_submission(_finding(), template="BUG: {title} [{severity}] on {affected_param}")
    assert md == "BUG: Reflected XSS in search [high] on q"


def test_render_custom_template_unknown_field_is_blank():
    md = render_submission(_finding(), template="{title}::{nonexistent_field}")
    assert md == "Reflected XSS in search::"


def test_default_template_has_all_sections():
    for section in ("Steps to Reproduce", "Impact", "Remediation", "References"):
        assert section in DEFAULT_SUBMISSION_TEMPLATE


def test_write_submissions_markdown_and_json(tmp_path):
    report = AgentReport(agent_name="hunter", kind=AgentKind.BUG_BOUNTY, findings=[_finding()])
    cfg = SubmissionConfig(enabled=True, formats=["markdown", "json"])
    written = write_submissions([report], cfg, Path(tmp_path))
    assert len(written) == 2
    md = next(p for p in written if p.endswith(".md"))
    js = next(p for p in written if p.endswith(".json"))
    assert "Reflected XSS" in Path(md).read_text()
    import json

    data = json.loads(Path(js).read_text())
    assert data["affected_param"] == "q"


def test_write_submissions_disabled(tmp_path):
    report = AgentReport(agent_name="h", kind=AgentKind.BUG_BOUNTY, findings=[_finding()])
    cfg = SubmissionConfig(enabled=False)
    assert write_submissions([report], cfg, Path(tmp_path)) == []


def test_write_submissions_falls_back_to_default_formats(tmp_path):
    report = AgentReport(agent_name="h", kind=AgentKind.BUG_BOUNTY, findings=[_finding()])
    cfg = SubmissionConfig(enabled=True, formats=[])
    written = write_submissions([report], cfg, Path(tmp_path), default_formats=["markdown"])
    assert len(written) == 1
    assert written[0].endswith(".md")
