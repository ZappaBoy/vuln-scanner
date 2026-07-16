"""Aggregate assessment model consumed by reporters and the LLM analyzer."""


from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from vuln_scanner.tools.enums import ScanStatus, Severity
from vuln_scanner.tools.models import Finding, ScanResult


class Cluster(BaseModel):
    """A root-cause grouping of related findings across tools/targets."""
    id: str
    title: str
    severity: Severity
    summary: str
    member_ids: list[str] = Field(default_factory=list)  # Finding identity refs
    shared_remediation: str = ""
    tags: list[str] = Field(default_factory=list)


class AssessmentStats(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_tool: dict[str, int] = Field(default_factory=dict)
    targets_scanned: int = 0
    tools_run: int = 0
    tools_skipped: int = 0
    tools_failed: int = 0
    total_duration: float = 0.0
    generated_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


def _compute_stats(results: list[ScanResult]) -> AssessmentStats:
    stats = AssessmentStats()
    seen_targets: set[str] = set()
    seen_tools: set[str] = set()

    for r in results:
        seen_targets.add(r.target)
        seen_tools.add(r.tool)
        stats.total_duration += r.duration

        if r.status == ScanStatus.SKIPPED:
            stats.tools_skipped += 1
        elif r.status == ScanStatus.FAILED:
            stats.tools_failed += 1

        for f in r.findings:
            stats.total_findings += 1
            sev = f.severity.value
            stats.by_severity[sev] = stats.by_severity.get(sev, 0) + 1
            stats.by_tool[f.tool] = stats.by_tool.get(f.tool, 0) + 1

    stats.targets_scanned = len(seen_targets)
    stats.tools_run = len(seen_tools)
    return stats


class Assessment(BaseModel):
    """Top-level result produced by a full scan, passed to reporters."""
    results: list[ScanResult] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    executive_summary: str = ""
    stats: AssessmentStats = Field(default_factory=AssessmentStats)
    # Paths to PoC asset files generated during this assessment
    poc_asset_paths: list[str] = Field(default_factory=list)
    # Arbitrary metadata (scan config snapshot, etc.)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_results(
        cls,
        results: list[ScanResult],
        *,
        clusters: list[Cluster] | None = None,
        executive_summary: str = "",
        poc_asset_paths: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "Assessment":
        return cls(
            results=results,
            clusters=clusters or [],
            executive_summary=executive_summary,
            stats=_compute_stats(results),
            poc_asset_paths=poc_asset_paths or [],
            metadata=metadata or {},
        )

    @property
    def all_findings(self) -> list[tuple[str, Finding]]:
        """Flat list of (tool_name, Finding) across all results, sorted by severity."""
        pairs = [
            (r.tool, f)
            for r in self.results
            for f in r.findings
        ]
        pairs.sort(key=lambda x: x[1].severity.sort_order)
        return pairs
