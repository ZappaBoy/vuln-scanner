"""Aggregate assessment model consumed by reporters and the LLM analyzer."""

from dataclasses import dataclass
from dataclasses import field as dc_field
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
    member_ids: list[str] = Field(default_factory=list)
    shared_remediation: str = ""
    tags: list[str] = Field(default_factory=list)


# ── Pipeline-level deduplication ─────────────────────────────────────────────


@dataclass
class FindingGroup:
    """A set of identical findings (same target + title) collapsed across tools.

    ``finding`` holds the richest representative (most fields populated).
    ``found_by`` lists every tool that reported it.
    """

    finding: Finding
    found_by: list[str] = dc_field(default_factory=list)

    def merge(self, tool: str, other: Finding) -> None:
        """Absorb another report of the same finding from a different tool."""
        if tool not in self.found_by:
            self.found_by.append(tool)
        # Prefer the richer finding
        if not self.finding.cvss_score and other.cvss_score:
            self.finding = other
        elif not self.finding.cve and other.cve:
            self.finding = other
        elif not self.finding.mitigation and other.mitigation:
            self.finding = other


def deduplicate_findings(pairs: list[tuple[str, Finding]]) -> list[FindingGroup]:
    """Collapse identical findings (same target + title) from multiple tools.

    Order is first-seen; subsequent reports by other tools extend ``found_by``.
    """
    seen: dict[str, FindingGroup] = {}
    for tool, f in pairs:
        key = f"{f.target}::{f.title}"
        if key in seen:
            seen[key].merge(tool, f)
        else:
            seen[key] = FindingGroup(finding=f, found_by=[tool])
    return list(seen.values())


# ── Stats ─────────────────────────────────────────────────────────────────────


class AssessmentStats(BaseModel):
    total_findings: int = 0
    unique_findings: int = 0  # after cross-tool deduplication
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_tool: dict[str, int] = Field(default_factory=dict)
    targets_scanned: int = 0
    tools_run: int = 0
    tools_skipped: int = 0
    tools_failed: int = 0
    total_duration: float = 0.0
    generated_at: str = Field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


def _compute_stats(results: list[ScanResult]) -> AssessmentStats:
    stats = AssessmentStats()
    seen_targets: set[str] = set()
    seen_tools: set[str] = set()
    all_pairs: list[tuple[str, Finding]] = []

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
            all_pairs.append((r.tool, f))

    stats.targets_scanned = len(seen_targets)
    stats.tools_run = len(seen_tools)
    stats.unique_findings = len(deduplicate_findings(all_pairs))
    return stats


class Assessment(BaseModel):
    """Top-level result produced by a full scan, passed to reporters."""

    results: list[ScanResult] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    executive_summary: str = ""
    stats: AssessmentStats = Field(default_factory=AssessmentStats)
    poc_asset_paths: list[str] = Field(default_factory=list)
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
        pairs = [(r.tool, f) for r in self.results for f in r.findings]
        pairs.sort(key=lambda x: x[1].severity.sort_order)
        return pairs

    @property
    def deduplicated_findings(self) -> list[FindingGroup]:
        """All findings deduplicated across tools, sorted by severity."""
        groups = deduplicate_findings(self.all_findings)
        groups.sort(key=lambda g: g.finding.severity.sort_order)
        return groups
