"""Tests for LLM analyzer and PoC runner — mocked OpenAI client, no real network calls."""

import os
from unittest.mock import MagicMock

import pytest

from vuln_scanner.llm.features import LLMFeatures, resolve_features
from vuln_scanner.llm.models import LLMConfig
from vuln_scanner.model import Assessment
from vuln_scanner.poc.models import PocVerdict
from vuln_scanner.poc.runner import PocRunner, _is_in_container
from vuln_scanner.tools.enums import Confidence, ScanStatus, Severity
from vuln_scanner.tools.models import Finding, ScanResult


def _finding(title="SQLi", severity=Severity.HIGH) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description="SQL injection in login.",
        tool="sqlmap",
        target="http://target.com",
    )


def _result(findings=None) -> ScanResult:
    return ScanResult(
        tool="sqlmap",
        target="http://target.com",
        findings=findings or [_finding()],
        status=ScanStatus.SUCCESS,
        raw_output="sqlmap output here",
    )


def _config(enabled=True, model="gpt-4o", **kw) -> LLMConfig:
    return LLMConfig(enabled=enabled, api_key="sk-test", model=model, **kw)


# ─── LLMFeatures ──────────────────────────────────────────────────────────────


class TestLLMFeatures:
    def test_defaults(self):
        f = LLMFeatures()
        assert f.logs_analysis is True
        assert f.generate_poc is True
        assert f.execute_poc is False

    def test_merge_override(self):
        base = LLMFeatures()
        override = LLMFeatures(generate_poc=False, execute_poc=True)
        merged = base.merge(override)
        assert merged.generate_poc is False
        assert merged.execute_poc is True
        assert merged.logs_analysis is True  # unchanged

    def test_resolve_tool_wins_over_category(self):
        global_f = LLMFeatures(generate_poc=True)
        cat_f = LLMFeatures(generate_poc=False)
        tool_f = LLMFeatures(generate_poc=True)
        result = resolve_features(global_f, {"sqlmap": tool_f}, {"web": cat_f}, "sqlmap", "web")
        assert result.generate_poc is True  # tool > category

    def test_resolve_category_wins_over_global(self):
        global_f = LLMFeatures(generate_poc=True)
        cat_f = LLMFeatures(generate_poc=False)
        result = resolve_features(global_f, {}, {"web": cat_f}, "sqlmap", "web")
        assert result.generate_poc is False  # category > global

    def test_resolve_no_overrides(self):
        global_f = LLMFeatures(generate_poc=False)
        result = resolve_features(global_f, {}, {}, "sqlmap", "web")
        assert result.generate_poc is False


# ─── LLMConfig ────────────────────────────────────────────────────────────────


class TestLLMConfig:
    def test_auto_enabled_with_key(self):
        cfg = LLMConfig(enabled="auto", api_key="sk-test", model="gpt-4o")
        assert cfg.is_active is True

    def test_auto_disabled_without_key(self):
        cfg = LLMConfig(enabled="auto", api_key="", model="gpt-4o")
        assert cfg.is_active is False

    def test_force_enabled(self):
        cfg = LLMConfig(enabled=True, api_key="", model="gpt-4o")
        assert cfg.is_active is True

    def test_force_disabled(self):
        cfg = LLMConfig(enabled=False, api_key="sk-test", model="gpt-4o")
        assert cfg.is_active is False

    def test_validate_active_fails_without_model(self):
        cfg = LLMConfig(enabled=True, api_key="sk-test", model="")
        with pytest.raises(ValueError, match="llm.model"):
            cfg.validate_active()

    def test_validate_active_passes_with_model(self):
        cfg = LLMConfig(enabled=True, api_key="sk-test", model="gpt-4o")
        cfg.validate_active()  # should not raise

    def test_in_scope_include_tools(self):
        cfg = LLMConfig(enabled=True, api_key="sk-test", model="m", include_tools=["sqlmap"])
        assert cfg.in_scope("sqlmap", "web") is True
        assert cfg.in_scope("nmap", "network") is False

    def test_in_scope_exclude_tools(self):
        cfg = LLMConfig(enabled=True, api_key="sk-test", model="m", exclude_tools=["checkov"])
        assert cfg.in_scope("checkov", "iac") is False
        assert cfg.in_scope("nmap", "network") is True

    def test_in_scope_exclude_category(self):
        cfg = LLMConfig(enabled=True, api_key="sk-test", model="m", exclude_categories=["iac"])
        assert cfg.in_scope("checkov", "iac") is False
        assert cfg.in_scope("sqlmap", "web") is True


# ─── LLMAnalyzer (mocked client) ──────────────────────────────────────────────


class TestLLMAnalyzer:
    def _make_client_mock(self, return_value: dict) -> MagicMock:
        mock = MagicMock()
        mock.complete_json.return_value = return_value
        return mock

    def test_skips_when_disabled(self):
        from vuln_scanner.llm.analyzer import LLMAnalyzer

        cfg = LLMConfig(enabled=False, api_key="", model="")
        assessment = Assessment.from_results([_result()])
        result = LLMAnalyzer(cfg).analyze(assessment)
        assert result.executive_summary == ""

    def test_enriches_finding_cwe(self):
        from vuln_scanner.llm.analyzer import LLMAnalyzer

        cfg = _config()
        assessment = Assessment.from_results([_result()])
        analyzer = LLMAnalyzer(cfg)
        analyzer._client = self._make_client_mock(
            {
                "cwe": ["CWE-89"],
                "confidence": "high",
                "false_positive": False,
                "exploitability": "Easy to exploit.",
                "notes": "Classic SQLi.",
                "poc_plan": "Use sqlmap -u URL.",
            }
        )
        result = analyzer.analyze(assessment)
        finding = result.results[0].findings[0]
        assert "CWE-89" in finding.cwe
        assert finding.confidence == Confidence.HIGH
        assert finding.false_positive is False

    def test_enriches_mitigation(self):
        from vuln_scanner.llm.analyzer import LLMAnalyzer

        cfg = _config()
        assessment = Assessment.from_results([_result()])
        analyzer = LLMAnalyzer(cfg)

        call_responses = [
            # Single combined triage + mitigation call
            {
                "cwe": [],
                "confidence": "medium",
                "false_positive": False,
                "exploitability": "",
                "notes": "",
                "poc_plan": "",
                "mitigation": "Use WAF.",
                "remediation": "Use prepared statements.",
            },
        ]
        analyzer._client = MagicMock()
        analyzer._client.complete_json.side_effect = call_responses
        result = analyzer.analyze(assessment)
        finding = result.results[0].findings[0]
        assert finding.mitigation == "Use WAF."
        assert finding.remediation == "Use prepared statements."

    def test_clusters_on_findings(self):
        from vuln_scanner.llm.analyzer import LLMAnalyzer

        cfg = _config()
        assessment = Assessment.from_results([_result()])
        analyzer = LLMAnalyzer(cfg)

        triage_resp = {
            "cwe": [],
            "confidence": "high",
            "false_positive": False,
            "exploitability": "",
            "notes": "",
            "poc_plan": "",
            "mitigation": "fix it",
            "remediation": "fix properly",
        }
        cluster_resp = {
            "executive_summary": "One critical finding.",
            "clusters": [
                {
                    "id": "cluster-1",
                    "title": "Injection cluster",
                    "severity": "high",
                    "summary": "SQL injection in multiple endpoints.",
                    "member_titles": ["SQLi"],
                    "shared_remediation": "Use ORM.",
                    "tags": ["injection"],
                }
            ],
        }
        analyzer._client = MagicMock()
        analyzer._client.complete_json.side_effect = [triage_resp, cluster_resp]
        result = analyzer.analyze(assessment)
        assert result.executive_summary == "One critical finding."
        assert len(result.clusters) == 1
        assert result.clusters[0].title == "Injection cluster"


# ─── PoC runner safety guard ──────────────────────────────────────────────────


class TestPocRunnerContainerGuard:
    def test_is_in_container_false_by_default(self):
        env_backup = os.environ.pop("VS_IN_CONTAINER", None)
        try:
            assert _is_in_container() is False
        finally:
            if env_backup is not None:
                os.environ["VS_IN_CONTAINER"] = env_backup

    def test_is_in_container_true_when_set(self):
        os.environ["VS_IN_CONTAINER"] = "1"
        try:
            assert _is_in_container() is True
        finally:
            del os.environ["VS_IN_CONTAINER"]

    def test_runner_refuses_without_marker(self):
        from vuln_scanner.poc.models import Poc

        env_backup = os.environ.pop("VS_IN_CONTAINER", None)
        try:
            cfg = LLMConfig(
                enabled=True,
                api_key="sk-test",
                model="gpt-4o",
                features=LLMFeatures(execute_poc=True),
            )
            runner = PocRunner(cfg)
            poc = Poc(id="poc-001", language="bash", script="echo vulnerable", safe_to_run=True)
            assessment = Assessment.from_results([_result()])
            result_pocs = runner.run_all([poc], assessment)
            # Should not execute — verdict stays NOT_RUN
            assert result_pocs[0].verdict == PocVerdict.NOT_RUN
        finally:
            if env_backup is not None:
                os.environ["VS_IN_CONTAINER"] = env_backup

    def test_runner_skips_when_execute_poc_disabled(self):
        from vuln_scanner.poc.models import Poc

        os.environ["VS_IN_CONTAINER"] = "1"
        try:
            cfg = LLMConfig(
                enabled=True,
                api_key="sk-test",
                model="gpt-4o",
                features=LLMFeatures(execute_poc=False),
            )
            runner = PocRunner(cfg)
            poc = Poc(id="poc-001", language="bash", script="echo hi", safe_to_run=True)
            assessment = Assessment.from_results([_result()])
            result_pocs = runner.run_all([poc], assessment)
            assert result_pocs[0].verdict == PocVerdict.NOT_RUN
        finally:
            del os.environ["VS_IN_CONTAINER"]


# ─── PoC denylist ─────────────────────────────────────────────────────────────


class TestPocDenylist:
    def test_rm_rf_blocked(self):
        from vuln_scanner.poc.generator import _is_safe

        safe, reason = _is_safe("rm -rf /")
        assert safe is False

    def test_fork_bomb_blocked(self):
        from vuln_scanner.poc.generator import _is_safe

        safe, reason = _is_safe(":(){ :|:& };:")
        assert safe is False

    def test_safe_curl_allowed(self):
        from vuln_scanner.poc.generator import _is_safe

        safe, reason = _is_safe("curl -s http://target.com/login")
        assert safe is True

    def test_safe_python_allowed(self):
        from vuln_scanner.poc.generator import _is_safe

        safe, reason = _is_safe("import requests\nr = requests.get('http://t.com')")
        assert safe is True


# ─── Assessment model ──────────────────────────────────────────────────────────


class TestAssessment:
    def test_stats_computed(self):
        r = _result(findings=[_finding("SQLi", Severity.CRITICAL)])
        a = Assessment.from_results([r])
        assert a.stats.total_findings == 1
        assert a.stats.by_severity.get("critical") == 1
        assert a.stats.targets_scanned == 1

    def test_all_findings_sorted(self):
        findings = [
            _finding("info", Severity.INFO),
            _finding("critical", Severity.CRITICAL),
        ]
        a = Assessment.from_results([_result(findings=findings)])
        titles = [f.title for _, f in a.all_findings]
        assert titles.index("critical") < titles.index("info")

    def test_finding_backward_compat(self):
        f = Finding(
            title="old",
            severity=Severity.LOW,
            description="d",
            tool="t",
            target="x",
        )
        assert f.cwe == []
        assert f.confidence == Confidence.UNKNOWN
        assert f.false_positive is None
