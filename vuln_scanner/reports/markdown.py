"""Professional Markdown reporter.

Produces a structured security assessment report following industry conventions:
numbered sections, finding IDs, business impact, evidence, scope/methodology,
and a clean appendix for scan errors and PoC assets.
"""


import re
from collections import defaultdict
from pathlib import Path

from vuln_scanner.model import Assessment, Cluster
from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.enums import Confidence, ScanStatus, Severity, severity_passes
from vuln_scanner.tools.models import Finding, ScanResult

# ── Severity ordering and labels ──────────────────────────────────────────────

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}

_SEVERITY_INDICATOR = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🔵 LOW",
    Severity.INFO:     "⚪ INFO",
}

_SEVERITY_RISK = {
    Severity.CRITICAL: "Immediate exploitation likely; maximum business impact.",
    Severity.HIGH:     "Significant risk; exploitation probable with minimal effort.",
    Severity.MEDIUM:   "Moderate risk; exploitation requires specific conditions.",
    Severity.LOW:      "Limited risk; exploitation is difficult or low-impact.",
    Severity.INFO:     "Informational; no direct exploitability demonstrated.",
}

_CONFIDENCE_LABEL = {
    Confidence.HIGH:    "High",
    Confidence.MEDIUM:  "Medium",
    Confidence.LOW:     "Low",
    Confidence.UNKNOWN: "Unknown",
}

_BAR_CHAR = "█"
_BAR_MAX = 20


# ── Helpers ───────────────────────────────────────────────────────────────────

def _escape_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def _bar(count: int, total: int) -> str:
    if not total or not count:
        return "—"
    filled = max(1, round((count / total) * _BAR_MAX))
    return _BAR_CHAR * filled


def _anchor(s: str) -> str:
    s = s.lower().replace(" ", "-")
    return re.sub(r"[^a-z0-9\-]", "", s)


def _fmt_ts(ts: str) -> str:
    return ts.split(".")[0].replace("T", " ").replace("+00:00", "") + " UTC"


# ── Deduplication ─────────────────────────────────────────────────────────────

class _FindingGroup:
    """Collapses identical findings (same title + target) from multiple tools."""

    def __init__(self, finding: Finding, tool: str) -> None:
        self.finding = finding
        self.tools: list[str] = [tool]
        self.fid: str = ""   # assigned by the renderer

    def add_tool(self, tool: str) -> None:
        if tool not in self.tools:
            self.tools.append(tool)


def _deduplicate(pairs: list[tuple[str, Finding]]) -> list[_FindingGroup]:
    seen: dict[str, _FindingGroup] = {}
    for tool, f in pairs:
        key = f"{f.target}::{f.title}"
        if key in seen:
            seen[key].add_tool(tool)
        else:
            seen[key] = _FindingGroup(f, tool)
    return list(seen.values())


# ── Reporter ──────────────────────────────────────────────────────────────────

class MarkdownReporter(AbstractReporter):

    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(self._render(assessment)), encoding="utf-8")
        return output_path

    # ── Top-level render ──────────────────────────────────────────────────────

    def _render(self, assessment: Assessment) -> list[str]:
        stats = assessment.stats

        # Pre-compute per-target data (needed for TOC and multiple sections)
        by_target: dict[str, list[ScanResult]] = defaultdict(list)
        for r in assessment.results:
            by_target[r.target].append(r)

        # Collect active targets and their deduplicated findings
        target_groups: dict[str, list[_FindingGroup]] = {}
        target_errors: dict[str, list[tuple[str, str]]] = {}
        for target in sorted(by_target):
            findings, errors = self._collect(by_target[target], self._min_severity)
            if findings or errors:
                groups = _deduplicate(findings)
                groups.sort(key=lambda g: _SEVERITY_ORDER.index(g.finding.severity))
                target_groups[target] = groups
                target_errors[target] = errors

        # Assign sequential finding IDs across all targets, ordered by severity
        all_groups: list[_FindingGroup] = []
        for groups in target_groups.values():
            all_groups.extend(groups)
        all_groups.sort(key=lambda g: _SEVERITY_ORDER.index(g.finding.severity))
        for idx, g in enumerate(all_groups, 1):
            g.fid = f"F-{idx:03d}"

        has_clusters = bool(assessment.clusters)
        has_errors = any(target_errors.values())
        has_pocs = bool(assessment.poc_asset_paths)
        active_targets = list(target_groups)

        lines: list[str] = []
        lines += self._section_cover(stats)
        lines += self._section_toc(active_targets, has_clusters, has_errors, has_pocs)
        lines += self._section_executive_summary(assessment)
        lines += self._section_scope(assessment, by_target, stats)
        lines += self._section_severity_guide()
        lines += self._section_findings_overview(stats, target_groups)
        if has_clusters:
            lines += self._section_clusters(assessment.clusters)
        findings_section = 6 if has_clusters else 5
        lines += self._section_detailed_findings(target_groups, section_num=findings_section)
        if has_errors:
            lines += self._appendix_errors(target_errors)
        if has_pocs:
            lines += self._appendix_pocs(assessment.poc_asset_paths)
        lines += ["", "---", "", f"*Report generated by vuln-scanner · {_fmt_ts(str(stats.generated_at))}*", ""]
        return lines

    # ── Cover page ────────────────────────────────────────────────────────────

    def _section_cover(self, stats) -> list[str]:
        ts = _fmt_ts(str(stats.generated_at))
        date = ts.split(" ")[0]
        return [
            "---",
            "",
            "# VULNERABILITY ASSESSMENT REPORT",
            "",
            "---",
            "",
            "| | |",
            "|:---|:---|",
            f"| **Classification** | CONFIDENTIAL |",
            f"| **Report Date** | {date} |",
            f"| **Assessment Type** | Automated Security Scan |",
            f"| **Targets Assessed** | {stats.targets_scanned} |",
            f"| **Total Findings** | {stats.total_findings} |",
            f"| **Report Version** | 1.0 |",
            "",
            "> **CONFIDENTIAL** — This report contains sensitive security information.",
            "> Distribution is restricted to authorized recipients only.",
            "",
            "---",
            "",
        ]

    # ── Table of contents ─────────────────────────────────────────────────────

    def _section_toc(
        self,
        active_targets: list[str],
        has_clusters: bool,
        has_errors: bool,
        has_pocs: bool,
    ) -> list[str]:
        lines = ["## Table of Contents", ""]
        n = 1
        sections = [
            "Executive Summary",
            "Scope and Methodology",
            "Severity Rating Guide",
            "Findings Overview",
        ]
        if has_clusters:
            sections.append("Vulnerability Clusters")
        sections.append("Detailed Findings")

        for title in sections:
            lines.append(f"{n}. [{title}](#{_anchor(title)})")
            n += 1

        if active_targets and "Detailed Findings" in sections:
            for t in active_targets:
                lines.append(f"   - [Target: {t}](#target-{_anchor(t)})")

        if has_errors:
            lines.append(f"\nAppendix A — [Scan Errors](#appendix-a--scan-errors)")
        if has_pocs:
            lines.append(f"Appendix B — [PoC Assets](#appendix-b--poc-assets)")

        lines += ["", "---", ""]
        return lines

    # ── Executive summary ─────────────────────────────────────────────────────

    def _section_executive_summary(self, assessment: Assessment) -> list[str]:
        summary = assessment.executive_summary or self._computed_summary(assessment)
        lines = ["## 1. Executive Summary", ""]
        for para in summary.strip().split("\n\n"):
            para = para.strip()
            if para:
                lines += [para, ""]
        lines += ["---", ""]
        return lines

    # ── Scope and methodology ─────────────────────────────────────────────────

    def _section_scope(
        self,
        assessment: Assessment,
        by_target: dict[str, list[ScanResult]],
        stats,
    ) -> list[str]:
        from vuln_scanner.tools.target import classify_target

        lines = [
            "## 2. Scope and Methodology",
            "",
            "### 2.1 Assessment Scope",
            "",
            "The following targets were included in this assessment:",
            "",
            "| # | Target | Type |",
            "|---|--------|------|",
        ]
        for i, target in enumerate(sorted(by_target), 1):
            types = ", ".join(t.value.upper() for t in classify_target(target))
            lines.append(f"| {i} | `{target}` | {types} |")

        lines += [
            "",
            "### 2.2 Tools Executed",
            "",
            "| Tool | Findings | Status |",
            "|------|:--------:|--------|",
        ]
        # Build per-tool status from results
        tool_status: dict[str, str] = {}
        tool_findings: dict[str, int] = dict(stats.by_tool)
        for r in assessment.results:
            if r.status.value in ("failed", "timeout"):
                tool_status[r.tool] = r.status.value.capitalize()
            elif r.tool not in tool_status:
                tool_status[r.tool] = "Success"

        for tool, count in sorted(stats.by_tool.items(), key=lambda x: -x[1]):
            status = tool_status.get(tool, "Success")
            lines.append(f"| `{tool}` | {count} | {status} |")

        lines += [
            "",
            "### 2.3 Scan Configuration",
            "",
            "| Parameter | Value |",
            "|-----------|-------|",
            f"| Scan duration | {stats.total_duration:.0f} seconds |",
            f"| Tools run | {stats.tools_run} |",
            f"| Tools with errors | {stats.tools_failed} |",
            f"| Tools skipped (binary not found) | {stats.tools_skipped} |",
            "",
            "---",
            "",
        ]
        return lines

    # ── Severity guide ────────────────────────────────────────────────────────

    def _section_severity_guide(self) -> list[str]:
        lines = [
            "## 3. Severity Rating Guide",
            "",
            "| Rating | CVSS Range | Description |",
            "|--------|:----------:|-------------|",
        ]
        ranges = {
            Severity.CRITICAL: "9.0 – 10.0",
            Severity.HIGH:     "7.0 – 8.9",
            Severity.MEDIUM:   "4.0 – 6.9",
            Severity.LOW:      "0.1 – 3.9",
            Severity.INFO:     "N/A",
        }
        for sev in _SEVERITY_ORDER:
            label = _SEVERITY_INDICATOR[sev]
            lines.append(f"| **{label}** | {ranges[sev]} | {_SEVERITY_RISK[sev]} |")
        lines += ["", "---", ""]
        return lines

    # ── Findings overview ─────────────────────────────────────────────────────

    def _section_findings_overview(
        self,
        stats,
        target_groups: dict[str, list[_FindingGroup]],
    ) -> list[str]:
        lines = [
            "## 4. Findings Overview",
            "",
            "### 4.1 Risk Distribution",
            "",
            "| Severity | Count | Distribution |",
            "|----------|------:|:-------------|",
        ]
        for sev in _SEVERITY_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            label = _SEVERITY_INDICATOR[sev]
            bar = _bar(count, stats.total_findings)
            lines.append(f"| {label} | {count} | {bar} |")

        lines += [
            "",
            "### 4.2 Findings by Target",
            "",
        ]

        # Build matrix: target × severity
        targets = sorted(target_groups)
        sev_cols = [s for s in _SEVERITY_ORDER if stats.by_severity.get(s.value, 0)]

        if targets and sev_cols:
            header = "| Target | " + " | ".join(_SEVERITY_LABEL[s] for s in sev_cols) + " | Total |"
            sep =    "|--------|" + "|".join([":------:"] * len(sev_cols)) + "|------:|"
            lines += [header, sep]

            for target in targets:
                groups = target_groups[target]
                counts = {s: 0 for s in sev_cols}
                for g in groups:
                    sev = g.finding.severity
                    if sev in counts:
                        counts[sev] += 1
                total = sum(counts.values())
                cells = " | ".join(str(counts[s]) if counts[s] else "—" for s in sev_cols)
                lines.append(f"| `{target}` | {cells} | **{total}** |")
        else:
            lines.append("*No findings recorded.*")

        lines += ["", "---", ""]
        return lines

    # ── Vulnerability clusters ────────────────────────────────────────────────

    def _section_clusters(self, clusters: list[Cluster]) -> list[str]:
        lines = ["## 5. Vulnerability Clusters", ""]
        sorted_clusters = sorted(clusters, key=lambda c: _SEVERITY_ORDER.index(c.severity))

        for idx, cluster in enumerate(sorted_clusters, 1):
            label = _SEVERITY_INDICATOR[cluster.severity]
            tags = ", ".join(cluster.tags) if cluster.tags else "—"
            lines += [
                f"### Cluster {idx} — {cluster.title}",
                "",
                f"| | |",
                f"|:---|:---|",
                f"| **Severity** | {label} |",
                f"| **Affected Findings** | {len(cluster.member_ids)} |",
                f"| **Tags** | {tags} |",
                "",
                cluster.summary,
                "",
            ]
            if cluster.shared_remediation:
                lines += [
                    "**Shared Remediation**",
                    "",
                    cluster.shared_remediation,
                    "",
                ]
            lines.append("")

        lines += ["---", ""]
        return lines

    # ── Detailed findings ─────────────────────────────────────────────────────

    def _section_detailed_findings(
        self,
        target_groups: dict[str, list[_FindingGroup]],
        section_num: int = 6,
    ) -> list[str]:
        lines = [f"## {section_num}. Detailed Findings", ""]

        for target in sorted(target_groups):
            lines += self._render_target(target, target_groups[target])

        return lines

    def _render_target(
        self,
        target: str,
        groups: list[_FindingGroup],
    ) -> list[str]:
        if not groups:
            return []

        lines = [
            f"### Target: {target}",
            "",
        ]

        # Summary table for this target
        lines += [
            "| ID | Severity | Finding | Tool(s) | Confidence |",
            "|----|----------|---------|---------|:----------:|",
        ]
        for g in groups:
            f = g.finding
            label = _SEVERITY_LABEL[f.severity]
            tools = ", ".join(g.tools)
            conf = _CONFIDENCE_LABEL.get(f.confidence, "Unknown")
            title = _escape_cell(f.title)
            lines.append(f"| {g.fid} | {label} | {title} | {tools} | {conf} |")

        lines.append("")

        # Individual finding detail blocks
        for g in groups:
            lines += self._render_finding(g)

        return lines

    def _render_finding(self, group: _FindingGroup) -> list[str]:
        f = group.finding
        label = _SEVERITY_INDICATOR[f.severity]
        tools_str = ", ".join(group.tools)
        cwes = ", ".join(f.cwe) if f.cwe else "—"
        cves = ", ".join(f.cve) if f.cve else "—"
        conf = _CONFIDENCE_LABEL.get(f.confidence, "Unknown")
        cluster_ref = f.cluster_id or "—"

        lines: list[str] = [
            f"#### {group.fid} — {_escape_cell(f.title)}",
            "",
            "| Field | Detail |",
            "|:------|--------|",
            f"| **Identifier** | {group.fid} |",
            f"| **Severity** | {label} |",
            f"| **Status** | Open |",
            f"| **Affected System** | {f.target} |",
            f"| **Detected By** | {tools_str} |",
            f"| **Confidence** | {conf} |",
            f"| **CWE** | {cwes} |",
            f"| **CVEs** | {cves} |",
            f"| **Cluster** | {cluster_ref} |",
            "",
        ]

        # Description
        if f.description:
            lines += [
                "**Description**",
                "",
                f.description,
                "",
            ]

        # Business impact (from exploitability field)
        if f.exploitability:
            lines += [
                "**Business Impact**",
                "",
                f.exploitability,
                "",
            ]

        # LLM analyst note
        if f.llm_notes:
            lines += [
                "**Analyst Note**",
                "",
                f"> {f.llm_notes}",
                "",
            ]

        # Short-term mitigation
        if f.mitigation:
            lines += [
                "**Short-term Mitigation**",
                "",
                f.mitigation,
                "",
            ]

        # Permanent remediation
        if f.remediation:
            lines += [
                "**Permanent Remediation**",
                "",
                f.remediation,
                "",
            ]

        # PoC references
        if f.poc_ids:
            poc_refs = ", ".join(f"`{p}`" for p in f.poc_ids)
            lines += [
                "**Proof-of-Concept**",
                "",
                f"PoC scripts: {poc_refs} (see Appendix B)",
                "",
            ]

        lines.append("---")
        lines.append("")
        return lines

    # ── Appendices ────────────────────────────────────────────────────────────

    def _appendix_errors(
        self,
        target_errors: dict[str, list[tuple[str, str]]],
    ) -> list[str]:
        lines = [
            "## Appendix A — Scan Errors",
            "",
            "The following tools encountered errors during the assessment.",
            "These are tool execution failures, not security findings.",
            "",
            "| Target | Tool | Error |",
            "|--------|------|-------|",
        ]
        for target in sorted(target_errors):
            for tool, err in target_errors[target]:
                lines.append(f"| `{target}` | `{tool}` | {_escape_cell(err[:200])} |")
        lines += ["", "---", ""]
        return lines

    def _appendix_pocs(self, paths: list[str]) -> list[str]:
        lines = [
            "## Appendix B — PoC Assets",
            "",
            "The following proof-of-concept scripts were generated during analysis.",
            "Execute them **only inside the Docker container** against the isolated target environment.",
            "",
        ]
        for path in paths:
            lines.append(f"- `{path}`")
        lines += ["", "---", ""]
        return lines

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _collect(
        results: list[ScanResult],
        min_severity: str = "none",
    ) -> tuple[list[tuple[str, Finding]], list[tuple[str, str]]]:
        findings: list[tuple[str, Finding]] = []
        errors: list[tuple[str, str]] = []
        for r in sorted(results, key=lambda x: x.tool):
            if r.status == ScanStatus.SKIPPED and not r.findings:
                continue
            if r.error and r.status not in (ScanStatus.SKIPPED,):
                errors.append((r.tool, r.error))
            for f in r.findings:
                if not f.false_positive and severity_passes(f.severity, min_severity):
                    findings.append((r.tool, f))
        return findings, errors

    @staticmethod
    def _computed_summary(assessment: Assessment) -> str:
        stats = assessment.stats
        if not stats.total_findings:
            return (
                "The automated security assessment completed without identifying any "
                "significant vulnerabilities across the assessed targets. The scan "
                "executed successfully against all in-scope systems."
            )
        sev_parts = []
        for sev in _SEVERITY_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            if count:
                sev_parts.append(f"{count} {sev.value.lower()}-severity")
        top_tools = sorted(stats.by_tool.items(), key=lambda x: -x[1])[:3]
        tools_str = ", ".join(t for t, _ in top_tools)
        return (
            f"The automated security assessment identified {stats.total_findings} finding(s) "
            f"across {stats.targets_scanned} target(s), comprising "
            f"{', '.join(sev_parts)}. "
            f"The primary contributing tools were {tools_str}. "
            f"Findings should be reviewed and triaged against the organization's risk tolerance "
            f"and remediation SLAs."
        )
