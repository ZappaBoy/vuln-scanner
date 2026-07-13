from pathlib import Path

import pytest

from vuln_scanner.reports.markdown import MarkdownReporter
from vuln_scanner.tools.base import Finding, ScanResult, ScanStatus, Severity


def _result(tool="nmap", target="10.0.0.1", findings=None, status=ScanStatus.SUCCESS, error=None):
    return ScanResult(
        tool=tool,
        target=target,
        findings=findings or [],
        duration=1.5,
        status=status,
        error=error,
    )


def _finding(title="Open port 22/tcp", severity=Severity.HIGH):
    return Finding(
        title=title,
        severity=severity,
        description="Test finding description.",
        tool="nmap",
        target="10.0.0.1",
    )


def test_report_creates_file(tmp_path):
    out = tmp_path / "report.md"
    MarkdownReporter().generate([_result()], out)
    assert out.exists()


def test_report_returns_path(tmp_path):
    out = tmp_path / "report.md"
    written = MarkdownReporter().generate([_result()], out)
    assert written == out


def test_report_contains_header(tmp_path):
    out = tmp_path / "report.md"
    MarkdownReporter().generate([_result()], out)
    content = out.read_text()
    assert "# Vulnerability Scan Report" in content


def test_report_summary_table(tmp_path):
    out = tmp_path / "report.md"
    MarkdownReporter().generate([_result(tool="nmap", target="10.0.0.1")], out)
    content = out.read_text()
    assert "nmap" in content
    assert "10.0.0.1" in content


def test_report_finding_appears(tmp_path):
    out = tmp_path / "report.md"
    findings = [_finding("Open port 22/tcp", Severity.HIGH)]
    MarkdownReporter().generate([_result(findings=findings)], out)
    content = out.read_text()
    assert "Open port 22/tcp" in content
    assert "HIGH" in content


def test_report_no_findings_message(tmp_path):
    out = tmp_path / "report.md"
    MarkdownReporter().generate([_result()], out)
    assert "No findings" in out.read_text()


def test_report_error_shown(tmp_path):
    out = tmp_path / "report.md"
    r = _result(status=ScanStatus.FAILED, error="Binary not found")
    MarkdownReporter().generate([r], out)
    assert "Binary not found" in out.read_text()


def test_report_severity_order(tmp_path):
    out = tmp_path / "report.md"
    findings = [
        _finding("info finding", Severity.INFO),
        _finding("critical finding", Severity.CRITICAL),
        _finding("medium finding", Severity.MEDIUM),
    ]
    MarkdownReporter().generate([_result(findings=findings)], out)
    content = out.read_text()
    assert content.index("CRITICAL") < content.index("MEDIUM") < content.index("INFO")


def test_report_creates_parent_dirs(tmp_path):
    out = tmp_path / "nested" / "dir" / "report.md"
    MarkdownReporter().generate([_result()], out)
    assert out.exists()


def test_report_multiple_results(tmp_path):
    out = tmp_path / "report.md"
    results = [
        _result(tool="nmap", target="10.0.0.1"),
        _result(tool="nikto", target="10.0.0.2"),
    ]
    MarkdownReporter().generate(results, out)
    content = out.read_text()
    assert "nmap" in content
    assert "nikto" in content
    assert "10.0.0.1" in content
    assert "10.0.0.2" in content
