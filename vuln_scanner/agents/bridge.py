"""Bridge agent-discovered bugs into the main findings pipeline.

Agent findings live in ``Assessment.agent_reports`` (their own provenance), but
they must also count toward severity stats and be eligible for LLM clustering /
executive summary.  This converts each ``AgentFinding`` into a standard
``Finding`` wrapped in a synthetic ``ScanResult`` tagged ``agent:<name>`` so the
rest of the pipeline treats them like any other finding.
"""

from vuln_scanner.agents.models import AgentFinding, AgentReport
from vuln_scanner.tools.enums import Confidence, ScanStatus
from vuln_scanner.tools.models import Finding, ScanResult


def _to_confidence(value: str) -> Confidence:
    try:
        return Confidence(value.lower())
    except (ValueError, AttributeError):
        return Confidence.UNKNOWN


def _to_finding(report: AgentReport, f: AgentFinding) -> Finding:
    tool = f"agent:{f.discovered_by or report.agent_name}"
    description = f.summary or f.impact or f.title
    target = f.target or f.affected_url or "agent"
    return Finding(
        title=f.title,
        severity=f.severity,
        description=description,
        tool=tool,
        target=target,
        cve=[],
        references=list(f.references),
        cwe=list(f.vuln_class),
        request=f.request,
        response=f.response,
        remediation=f.remediation,
        confidence=_to_confidence(f.confidence),
        exploitability=f.impact,
        cvss_vector=f.cvss_vector,
        cvss_score=f.cvss_score,
        raw={"agent": report.agent_name, "verified": f.verified, "oob_evidence": f.oob_evidence},
    )


def agent_reports_to_results(reports: list[AgentReport]) -> list[ScanResult]:
    """Convert agent findings into synthetic ScanResults (one per finding)."""
    results: list[ScanResult] = []
    for report in reports:
        for f in report.findings:
            finding = _to_finding(report, f)
            results.append(
                ScanResult(
                    tool=finding.tool,
                    target=finding.target,
                    findings=[finding],
                    status=ScanStatus.SUCCESS,
                )
            )
    return results


def bridge_into_assessment(assessment) -> int:
    """Append agent findings to ``assessment.results`` and refresh stats.

    Idempotent guard: skips if agent results are already present.  Returns the
    number of findings bridged.
    """
    if any(r.tool.startswith("agent:") for r in assessment.results):
        return 0
    bridged = agent_reports_to_results(assessment.agent_reports)
    if not bridged:
        return 0
    assessment.results.extend(bridged)
    assessment.refresh_stats()
    return sum(len(r.findings) for r in bridged)
