"""LLM response logging — one-line summaries surfaced to logs while running."""

import logging
from argparse import Namespace

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.llm.analyzer import LLMAnalyzer, _oneline
from vuln_scanner.llm.models import LLMConfig
from vuln_scanner.model import Assessment
from vuln_scanner.tools.enums import ScanStatus, Severity
from vuln_scanner.tools.models import Finding, ScanResult


def _args(**kwargs) -> Namespace:
    base = build_arg_parser().parse_args([])
    for k, v in kwargs.items():
        setattr(base, k, v)
    return base


class _FakeClient:
    """Returns a canned triage/cluster response without any network."""

    def __init__(self, payload):
        self._payload = payload

    def complete_json(self, system, user):
        return self._payload


def _finding() -> Finding:
    return Finding(title="SQLi in id", severity=Severity.HIGH, description="d", tool="sqlmap", target="t")


# ── config wiring ─────────────────────────────────────────────────────────────


def test_log_responses_default_true():
    assert LLMConfig(model="m").log_responses is True


def test_env_disables_log_responses(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VS_LLM_LOG_RESPONSES", "false")
    cfg = load_config(_args())
    assert cfg.build_llm_config().log_responses is False


# ── _oneline helper ───────────────────────────────────────────────────────────


def test_oneline_collapses_and_truncates():
    assert _oneline("a\n  b   c", 100) == "a b c"
    out = _oneline("x" * 50, 10)
    assert len(out) == 10 and out.endswith("…")


# ── triage response logging ───────────────────────────────────────────────────


def _analyzer(payload, *, log_responses=True) -> tuple[LLMAnalyzer, Assessment]:
    cfg = LLMConfig(enabled=True, api_key="k", model="m", min_severity="info", log_responses=log_responses)
    analyzer = LLMAnalyzer(cfg)
    analyzer._client = _FakeClient(payload)
    result = ScanResult(tool="sqlmap", target="t", findings=[_finding()], status=ScanStatus.SUCCESS)
    assessment = Assessment.from_results([result])
    return analyzer, assessment


_TRIAGE = {
    "cwe": ["CWE-89"],
    "confidence": "high",
    "false_positive": False,
    "exploitability": "trivial",
    "cvss_score": 8.1,
    "poc_plan": "inject ' OR 1=1",
}


def test_triage_logs_one_line(caplog):
    analyzer, assessment = _analyzer(_TRIAGE)
    with caplog.at_level(logging.INFO, logger="vuln_scanner.llm.analyzer"):
        analyzer._triage_result(assessment.results[0])
    line = next((r.message for r in caplog.records if "LLM triage ·" in r.message), None)
    assert line is not None
    assert "conf=high" in line
    assert "CWE-89" in line
    assert "+poc-plan" in line


def test_triage_silent_when_disabled(caplog):
    analyzer, assessment = _analyzer(_TRIAGE, log_responses=False)
    with caplog.at_level(logging.INFO, logger="vuln_scanner.llm.analyzer"):
        analyzer._triage_result(assessment.results[0])
    assert not any("LLM triage ·" in r.message for r in caplog.records)


# ── cluster response logging ──────────────────────────────────────────────────


def test_cluster_logs_summary_and_clusters(caplog):
    payload = {
        "executive_summary": "Several critical injection flaws were confirmed.",
        "clusters": [{"id": "c1", "title": "Injection", "severity": "high", "member_titles": ["SQLi in id"]}],
    }
    analyzer, assessment = _analyzer(payload)
    with caplog.at_level(logging.INFO, logger="vuln_scanner.llm.analyzer"):
        analyzer._cluster(assessment)
    msgs = [r.message for r in caplog.records]
    assert any("LLM clusters ·" in m and "Injection" in m for m in msgs)
    assert any("LLM summary ·" in m and "injection flaws" in m for m in msgs)
