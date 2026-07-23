"""Tests for new tool parse_output implementations."""

import json

from vuln_scanner.tools.bearer import BearerTool
from vuln_scanner.tools.enums import Severity
from vuln_scanner.tools.govulncheck import GovulncheckTool
from vuln_scanner.tools.prowler import ProwlerTool

GOVULN_LINE = json.dumps(
    {
        "vuln": {
            "id": "GO-2023-1234",
            "summary": "A remote code execution vulnerability in example/pkg",
            "aliases": ["CVE-2023-1234"],
            "references": [{"url": "https://pkg.go.dev/vuln/GO-2023-1234"}],
            "modules": [{"path": "github.com/example/pkg"}],
        }
    }
)

GOVULN_PREAMBLE = '{"progress": {"message": "Scanning..."}}'


class TestGovulncheckParser:
    tool = GovulncheckTool()
    target = "/path/to/project"

    def test_parses_single_vuln(self):
        findings = self.tool.parse_output(GOVULN_LINE, self.target)
        assert len(findings) == 1
        f = findings[0]
        assert "GO-2023-1234" in f.title
        assert f.cve == ["CVE-2023-1234"]
        assert f.severity == Severity.HIGH
        assert f.target == self.target

    def test_ignores_non_vuln_lines(self):
        raw = f"{GOVULN_PREAMBLE}\n{GOVULN_LINE}"
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1

    def test_empty_output_returns_empty_list(self):
        assert self.tool.parse_output("", self.target) == []

    def test_malformed_json_line_is_skipped(self):
        raw = '{"vuln": bad json}\n' + GOVULN_LINE
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1

    def test_vuln_without_modules_is_skipped(self):
        line = json.dumps(
            {
                "vuln": {
                    "id": "GO-2023-9999",
                    "summary": "No modules listed",
                    "modules": [],
                }
            }
        )
        assert self.tool.parse_output(line, self.target) == []

    def test_multiple_modules_produce_multiple_findings(self):
        line = json.dumps(
            {
                "vuln": {
                    "id": "GO-2023-5555",
                    "summary": "Multi-module vuln",
                    "modules": [
                        {"path": "github.com/pkg/a"},
                        {"path": "github.com/pkg/b"},
                    ],
                }
            }
        )
        findings = self.tool.parse_output(line, self.target)
        assert len(findings) == 2


BEARER_JSON = {
    "critical": [
        {
            "id": "ruby_lang_sql_injection",
            "title": "SQL Injection via unsanitized input",
            "description": "User input directly interpolated into SQL query.",
            "filename": "app/models/user.rb",
            "line_number": 42,
            "cwe_ids": ["89"],
        }
    ],
    "high": [],
    "medium": [
        {
            "id": "ruby_lang_weak_cipher",
            "title": "Weak cipher used",
            "description": "AES-ECB detected.",
            "filename": "lib/crypto.rb",
            "line_number": 10,
            "cwe_ids": ["327"],
        }
    ],
    "low": [],
    "warning": [],
}


class TestBearerParser:
    tool = BearerTool()
    target = "/path/to/rails-app"

    def test_parses_critical_finding(self):
        findings = self.tool.parse_output(json.dumps(BEARER_JSON), self.target)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "sql_injection" in critical[0].title
        assert "CWE-89" in critical[0].cwe

    def test_parses_medium_finding(self):
        findings = self.tool.parse_output(json.dumps(BEARER_JSON), self.target)
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1
        assert "CWE-327" in medium[0].cwe

    def test_total_finding_count(self):
        findings = self.tool.parse_output(json.dumps(BEARER_JSON), self.target)
        assert len(findings) == 2

    def test_empty_string_returns_empty_list(self):
        assert self.tool.parse_output("", self.target) == []

    def test_invalid_json_returns_empty_list(self):
        assert self.tool.parse_output("not json at all", self.target) == []

    def test_description_includes_filename_and_line(self):
        findings = self.tool.parse_output(json.dumps(BEARER_JSON), self.target)
        critical = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert "app/models/user.rb" in critical.description
        assert "42" in critical.description


# Prowler outputs ASFF JSONL (one JSON object per line)
_PROWLER_FAIL = json.dumps(
    {
        "SchemaVersion": "2018-10-08",
        "Title": "S3 bucket public access block not enabled",
        "Description": "Bucket my-bucket has public access enabled.",
        "Severity": {"Label": "HIGH"},
        "Status": "FAIL",
        "Resources": [{"Id": "arn:aws:s3:::my-bucket", "Region": "us-east-1"}],
        "Remediation": {"Recommendation": {"Url": "https://docs.aws.amazon.com/s3/"}},
    }
)
_PROWLER_PASS = json.dumps(
    {
        "SchemaVersion": "2018-10-08",
        "Title": "CloudTrail enabled",
        "Description": "CloudTrail is enabled.",
        "Severity": {"Label": "MEDIUM"},
        "Status": "PASS",
        "Resources": [{"Id": "arn:aws:cloudtrail:us-east-1:123456789:trail/main", "Region": "us-east-1"}],
    }
)


class TestProwlerParser:
    tool = ProwlerTool()
    target = "aws:profile=default"

    def test_only_fail_status_produces_findings(self):
        raw = f"{_PROWLER_FAIL}\n{_PROWLER_PASS}\n"
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1
        assert "S3" in findings[0].title

    def test_severity_mapped_correctly(self):
        findings = self.tool.parse_output(_PROWLER_FAIL, self.target)
        assert findings[0].severity == Severity.HIGH

    def test_empty_string_returns_empty(self):
        assert self.tool.parse_output("", self.target) == []

    def test_non_json_lines_skipped(self):
        raw = "Prowler version 3.x\n" + _PROWLER_FAIL
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1

    def test_malformed_json_line_skipped(self):
        raw = "{bad json}\n" + _PROWLER_FAIL
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1
