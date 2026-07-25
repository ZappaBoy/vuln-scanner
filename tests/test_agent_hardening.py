"""M7 — secret scrubbing + independent verification."""

from pathlib import Path

from vuln_scanner.agents.models import (
    AgentFinding,
    AgentKind,
    AgentPoc,
    AgentReport,
    SandboxConfig,
)
from vuln_scanner.agents.scrub import scrub, scrub_report
from vuln_scanner.agents.verifier import verify_report
from vuln_scanner.tools.enums import Severity

# ── Scrubbing ─────────────────────────────────────────────────────────────────


def test_scrub_aws_key():
    assert "AKIA" not in scrub("key=AKIAIOSFODNN7EXAMPLE here")


def test_scrub_bearer_and_password():
    assert "hunter2" not in scrub("password: hunter2")
    assert "REDACTED" in scrub("authorization: Bearer abc123def456")


def test_scrub_private_key():
    blob = "-----BEGIN PRIVATE KEY-----\nMIIBVw...\n-----END PRIVATE KEY-----"
    assert "MIIBVw..." not in scrub(blob)


def test_scrub_leaves_benign_text():
    assert scrub("open port 443 on host") == "open port 443 on host"


def test_scrub_report_walks_all_fields():
    report = AgentReport(
        agent_name="h",
        kind=AgentKind.BUG_BOUNTY,
        summary="leaked api_key=sk-abcdefghij1234567890",
        findings=[
            AgentFinding(
                title="x",
                severity=Severity.HIGH,
                response="Set-Cookie: token=eyJhbGciOi.eyJzdWIiOi.abcdefghij",
                impact="password=secretpass exposed",
            )
        ],
        pocs=[AgentPoc(id="p1", evidence="AKIAIOSFODNN7EXAMPLE")],
    )
    scrub_report(report)
    assert "sk-abcdefghij1234567890" not in report.summary
    assert "AKIA" not in report.pocs[0].evidence
    assert "secretpass" not in report.findings[0].impact


# ── Verification ──────────────────────────────────────────────────────────────


def _report_with_poc(tmp_path, script: str, indicator: str, title="Bug") -> AgentReport:
    p = Path(tmp_path) / "poc.py"
    p.write_text(script)
    return AgentReport(
        agent_name="h",
        kind=AgentKind.BUG_BOUNTY,
        findings=[AgentFinding(title=title, severity=Severity.HIGH)],
        pocs=[
            AgentPoc(
                id="p1",
                finding_title=title,
                language="python",
                script_path=str(p),
                expected_indicator=indicator,
            )
        ],
    )


def test_verify_marks_finding_when_indicator_present(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    report = _report_with_poc(tmp_path, "print('VULN-CONFIRMED')", "VULN-CONFIRMED")
    n = verify_report(report, sandbox=SandboxConfig(timeout=10), code_languages=["python"])
    assert n == 1
    assert report.findings[0].verified is True
    assert report.pocs[0].verdict == "confirmed"


def test_verify_does_not_mark_when_indicator_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    report = _report_with_poc(tmp_path, "print('nothing here')", "VULN-CONFIRMED")
    n = verify_report(report, sandbox=SandboxConfig(timeout=10), code_languages=["python"])
    assert n == 0
    assert report.findings[0].verified is False


def test_verify_skips_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    report = _report_with_poc(tmp_path, "print('VULN-CONFIRMED')", "VULN-CONFIRMED")
    assert verify_report(report, sandbox=SandboxConfig(), code_languages=["python"]) == 0
    assert report.findings[0].verified is False
