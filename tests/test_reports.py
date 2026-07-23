"""Tests for all three reporters. All host-safe — no real tool execution."""

from vuln_scanner.model import Assessment, Cluster
from vuln_scanner.reports.html import HTMLReporter
from vuln_scanner.reports.json_reporter import JSONReporter
from vuln_scanner.reports.markdown import MarkdownReporter
from vuln_scanner.tools.enums import ScanStatus, Severity
from vuln_scanner.tools.models import Finding, ScanResult


def _finding(title="Open port 22/tcp", severity=Severity.HIGH, tool="nmap", target="10.0.0.1") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description="Test finding description.",
        tool=tool,
        target=target,
    )


def _result(
    tool="nmap",
    target="10.0.0.1",
    findings=None,
    status=ScanStatus.SUCCESS,
    error=None,
) -> ScanResult:
    return ScanResult(
        tool=tool,
        target=target,
        findings=findings or [],
        duration=1.5,
        status=status,
        error=error,
    )


def _assessment(*results: ScanResult, clusters=None, summary="") -> Assessment:
    return Assessment.from_results(
        list(results),
        clusters=clusters or [],
        executive_summary=summary,
    )


# ─── Markdown ─────────────────────────────────────────────────────────────────


class TestMarkdownReporter:
    def test_creates_file(self, tmp_path):
        out = tmp_path / "report.md"
        MarkdownReporter().generate(_assessment(_result()), out)
        assert out.exists()

    def test_returns_path(self, tmp_path):
        out = tmp_path / "report.md"
        written = MarkdownReporter().generate(_assessment(_result()), out)
        assert written == out

    def test_header_present(self, tmp_path):
        out = tmp_path / "report.md"
        MarkdownReporter().generate(_assessment(_result()), out)
        assert "VULNERABILITY ASSESSMENT REPORT" in out.read_text()

    def test_finding_appears(self, tmp_path):
        out = tmp_path / "report.md"
        MarkdownReporter().generate(_assessment(_result(findings=[_finding("Open port 22/tcp")])), out)
        content = out.read_text()
        assert "Open port 22/tcp" in content
        assert "HIGH" in content

    def test_no_finding_tool_omitted(self, tmp_path):
        out = tmp_path / "report.md"
        MarkdownReporter().generate(_assessment(_result()), out)
        content = out.read_text()
        assert "nmap" not in content

    def test_error_visible(self, tmp_path):
        out = tmp_path / "report.md"
        r = _result(status=ScanStatus.FAILED, error="Subprocess failed")
        MarkdownReporter().generate(_assessment(r), out)
        assert "Subprocess failed" in out.read_text()

    def test_severity_ordering(self, tmp_path):
        out = tmp_path / "report.md"
        r = _result(
            findings=[
                _finding("info", Severity.INFO),
                _finding("critical", Severity.CRITICAL),
                _finding("medium", Severity.MEDIUM),
            ]
        )
        MarkdownReporter().generate(_assessment(r), out)
        content = out.read_text()
        assert content.index("CRITICAL") < content.index("MEDIUM") < content.index("INFO")

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "nested" / "dir" / "report.md"
        MarkdownReporter().generate(_assessment(_result()), out)
        assert out.exists()

    def test_skipped_tools_hidden(self, tmp_path):
        out = tmp_path / "report.md"
        r = _result(tool="smbmap", status=ScanStatus.SKIPPED)
        MarkdownReporter().generate(_assessment(r), out)
        assert "smbmap" not in out.read_text()

    def test_false_positive_hidden(self, tmp_path):
        out = tmp_path / "report.md"
        f = _finding("FP finding")
        f.false_positive = True
        r = _result(findings=[f])
        MarkdownReporter().generate(_assessment(r), out)
        assert "FP finding" not in out.read_text()

    def test_executive_summary_present(self, tmp_path):
        out = tmp_path / "report.md"
        MarkdownReporter().generate(_assessment(_result(), summary="Critical issues found in network services."), out)
        assert "Critical issues found" in out.read_text()

    def test_cluster_section_present(self, tmp_path):
        out = tmp_path / "report.md"
        cluster = Cluster(
            id="c1",
            title="SQL Injection cluster",
            severity=Severity.HIGH,
            summary="SQLi found in login form.",
            shared_remediation="Use parameterised queries.",
        )
        MarkdownReporter().generate(_assessment(_result(), clusters=[cluster]), out)
        content = out.read_text()
        assert "SQL Injection cluster" in content
        assert "parameterised queries" in content

    def test_mitigation_in_detail_block(self, tmp_path):
        out = tmp_path / "report.md"
        f = _finding("XSS")
        f.mitigation = "Sanitize inputs immediately."
        f.remediation = "Use CSP headers and encode output."
        r = _result(findings=[f])
        MarkdownReporter().generate(_assessment(r), out)
        content = out.read_text()
        assert "Sanitize inputs immediately." in content
        assert "Use CSP headers" in content

    def test_poc_id_shown(self, tmp_path):
        out = tmp_path / "report.md"
        f = _finding("SQLi")
        f.poc_ids = ["poc-001"]
        r = _result(findings=[f])
        MarkdownReporter().generate(_assessment(r), out)
        assert "poc-001" in out.read_text()

    def test_cwe_shown(self, tmp_path):
        out = tmp_path / "report.md"
        f = _finding("XSS")
        f.cwe = ["CWE-79"]
        r = _result(findings=[f])
        MarkdownReporter().generate(_assessment(r), out)
        assert "CWE-79" in out.read_text()


# ─── HTML ─���───────────────────────────────────────────────────────────────────


class TestHTMLReporter:
    def test_creates_file(self, tmp_path):
        out = tmp_path / "report.html"
        HTMLReporter().generate(_assessment(_result()), out)
        assert out.exists()

    def test_valid_html_structure(self, tmp_path):
        out = tmp_path / "report.html"
        HTMLReporter().generate(_assessment(_result()), out)
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_finding_escaping(self, tmp_path):
        out = tmp_path / "report.html"
        f = _finding("<script>alert(1)</script>")
        r = _result(findings=[f])
        HTMLReporter().generate(_assessment(r), out)
        content = out.read_text()
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content

    def test_theme_toggle_script(self, tmp_path):
        out = tmp_path / "report.html"
        HTMLReporter().generate(_assessment(_result()), out)
        assert "toggleTheme" in out.read_text()


# ─── JSON ───────────────────────────────────────────────���─────────────────────


class TestJSONReporter:
    def test_creates_file(self, tmp_path):
        out = tmp_path / "report.json"
        JSONReporter().generate(_assessment(_result()), out)
        assert out.exists()

    def test_valid_json(self, tmp_path):
        import json

        out = tmp_path / "report.json"
        JSONReporter().generate(_assessment(_result()), out)
        data = json.loads(out.read_text())
        assert isinstance(data, dict)
        assert "results" in data
        assert "stats" in data

    def test_findings_in_json(self, tmp_path):
        import json

        out = tmp_path / "report.json"
        r = _result(findings=[_finding("SQLi", Severity.CRITICAL)])
        JSONReporter().generate(_assessment(r), out)
        data = json.loads(out.read_text())
        titles = [f["title"] for res in data["results"] for f in res["findings"]]
        assert "SQLi" in titles

    def test_clusters_in_json(self, tmp_path):
        import json

        out = tmp_path / "report.json"
        cluster = Cluster(
            id="c1",
            title="Network exposure",
            severity=Severity.HIGH,
            summary="Multiple open ports.",
            shared_remediation="Close unused ports.",
        )
        MarkdownReporter().generate(_assessment(_result(), clusters=[cluster]), tmp_path / "r.md")
        JSONReporter().generate(_assessment(_result(), clusters=[cluster]), out)
        data = json.loads(out.read_text())
        assert data["clusters"][0]["title"] == "Network exposure"


# ─── PDF ──────────────────────────────────────────────────────────────────────


class TestPDFReporter:
    def test_creates_file(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        get_reporter(ReportFormat.PDF).generate(_assessment(_result()), out)
        assert out.exists()

    def test_file_is_valid_pdf(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        get_reporter(ReportFormat.PDF).generate(_assessment(_result()), out)
        assert out.read_bytes()[:4] == b"%PDF"

    def test_returns_path(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        written = get_reporter(ReportFormat.PDF).generate(_assessment(_result()), out)
        assert written == out

    def test_nonzero_size(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        get_reporter(ReportFormat.PDF).generate(_assessment(_result(findings=[_finding()])), out)
        assert out.stat().st_size > 1000

    def test_creates_parent_dirs(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "nested" / "report.pdf"
        get_reporter(ReportFormat.PDF).generate(_assessment(_result()), out)
        assert out.exists()

    def test_multiple_findings(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        r = _result(
            findings=[
                _finding("SQLi", Severity.CRITICAL),
                _finding("XSS", Severity.HIGH),
                _finding("Info", Severity.INFO),
            ]
        )
        get_reporter(ReportFormat.PDF).generate(_assessment(r), out)
        assert out.exists() and out.stat().st_size > 1000

    def test_with_executive_summary(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        get_reporter(ReportFormat.PDF).generate(
            _assessment(_result(), summary="Critical infrastructure issues found."), out
        )
        assert out.exists()

    def test_min_severity_filter(self, tmp_path):
        from vuln_scanner.config.models import ReportFormat
        from vuln_scanner.reports import get_reporter

        out = tmp_path / "report.pdf"
        r = _result(
            findings=[
                _finding("Low finding", Severity.LOW),
                _finding("Critical finding", Severity.CRITICAL),
            ]
        )
        # Only critical should appear — but PDF is binary so we just test it runs
        get_reporter(ReportFormat.PDF, min_severity="high").generate(_assessment(r), out)
        assert out.exists()
