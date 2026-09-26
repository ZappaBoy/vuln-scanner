"""Bridge agent-discovered bugs into the main findings pipeline.

Agent findings live in ``Assessment.agent_reports`` (their own provenance), but
they must also count toward severity stats and be eligible for LLM clustering /
executive summary.  This converts each ``AgentFinding`` into a standard
``Finding`` wrapped in a synthetic ``ScanResult`` tagged ``agent:<name>`` so the
rest of the pipeline treats them like any other finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from vuln_scanner.agents.models import AgentReport
from vuln_scanner.tools.enums import ScanStatus
from vuln_scanner.tools.models import ScanResult

if TYPE_CHECKING:
    from vuln_scanner.model import Assessment

_AGENT_TOOL_PREFIX = "agent:"


def agent_reports_to_results(reports: list[AgentReport]) -> list[ScanResult]:
    """Convert agent findings into synthetic ScanResults (one per finding)."""
    results: list[ScanResult] = []
    for report in reports:
        for finding in report.findings:
            converted = finding.to_finding(report.agent_name)
            results.append(
                ScanResult(
                    tool=converted.tool,
                    target=converted.target,
                    findings=[converted],
                    status=ScanStatus.SUCCESS,
                )
            )
    return results


def bridge_into_assessment(assessment: "Assessment") -> int:
    """Append agent findings to ``assessment.results`` and refresh stats.

    Idempotent guard: skips if agent results are already present.  Returns the
    number of findings bridged.
    """
    if any(result.tool.startswith(_AGENT_TOOL_PREFIX) for result in assessment.results):
        return 0
    bridged = agent_reports_to_results(assessment.agent_reports)
    if not bridged:
        return 0
    assessment.results.extend(bridged)
    assessment.refresh_stats()
    return sum(len(result.findings) for result in bridged)
