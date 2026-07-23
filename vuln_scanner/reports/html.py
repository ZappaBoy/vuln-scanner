"""Self-contained professional HTML reporter."""

import html as _html
from collections import defaultdict
from pathlib import Path

from vuln_scanner.model import Assessment, deduplicate_findings
from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.enums import Confidence, ScanStatus, Severity, severity_passes
from vuln_scanner.tools.models import Finding, ScanResult

_SEV_COLOR = {
    Severity.CRITICAL: "#d32f2f",
    Severity.HIGH: "#e64a19",
    Severity.MEDIUM: "#f9a825",
    Severity.LOW: "#1565c0",
    Severity.INFO: "#546e7a",
}

_SEV_BG = {
    Severity.CRITICAL: "#ffebee",
    Severity.HIGH: "#fbe9e7",
    Severity.MEDIUM: "#fffde7",
    Severity.LOW: "#e3f2fd",
    Severity.INFO: "#eceff1",
}

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_CONF_LABEL = {
    Confidence.HIGH: "High",
    Confidence.MEDIUM: "Medium",
    Confidence.LOW: "Low",
    Confidence.UNKNOWN: "—",
}


def _e(s: str) -> str:
    return _html.escape(str(s))


def _badge(sev: Severity) -> str:
    color = _SEV_COLOR.get(sev, "#546e7a")
    return f'<span class="badge" style="background:{color}">{_e(sev.value.upper())}</span>'


_CSS = """
:root {
  --bg: #f8f9fa; --surface: #fff; --border: #dee2e6;
  --text: #212529; --muted: #6c757d; --accent: #1976d2;
  --crit: #d32f2f; --high: #e64a19; --med: #f9a825; --low: #1565c0; --info: #546e7a;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #121212; --surface: #1e1e1e; --border: #333; --text: #e0e0e0; --muted: #9e9e9e; }
}
:root[data-theme="dark"]  { --bg: #121212; --surface: #1e1e1e; --border: #333; --text: #e0e0e0; --muted: #9e9e9e; }
:root[data-theme="light"] { --bg: #f8f9fa; --surface: #fff; --border: #dee2e6; --text: #212529; --muted: #6c757d; }
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; padding: 0; font-family: system-ui,-apple-system,sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
a { color: var(--accent); }
h1,h2,h3,h4 { margin: 1.2rem 0 0.4rem; }
.container { max-width: 1200px; margin: 0 auto; padding: 1.5rem 2rem; }
.hero { background: var(--accent); color: #fff; padding: 2rem; margin-bottom: 2rem; border-radius: 0.5rem; }
.hero h1 { margin: 0 0 0.5rem; font-size: 1.8rem; }
.hero .meta { opacity: 0.85; font-size: 0.9rem; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; text-align: center; }
.stat-card .num { font-size: 2rem; font-weight: 700; }
.stat-card .label { font-size: 0.8rem; color: var(--muted); }
.section { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; }
.exec-summary { border-left: 4px solid var(--accent); padding-left: 1rem; color: var(--text); }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; overflow-x: auto; display: block; }
th { background: var(--border); padding: 0.5rem 0.75rem; text-align: left; white-space: nowrap; }
td { padding: 0.4rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: var(--bg); }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 0.25rem; color: #fff; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
.cluster-card { border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem 1.25rem; margin-bottom: 1rem; }
.cluster-card h4 { margin: 0 0 0.5rem; }
details summary { cursor: pointer; font-weight: 600; padding: 0.25rem 0; }
details[open] summary { margin-bottom: 0.75rem; }
.finding-detail { background: var(--bg); border: 1px solid var(--border); border-radius: 0.4rem; padding: 0.75rem 1rem; margin-top: 0.5rem; font-size: 0.875rem; }
.finding-detail h5 { margin: 0.5rem 0 0.25rem; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.finding-detail pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
code { background: var(--border); padding: 0.1rem 0.3rem; border-radius: 0.2rem; font-size: 0.85em; }
.theme-toggle { float: right; cursor: pointer; background: rgba(255,255,255,0.2); border: none; color: #fff; padding: 0.3rem 0.75rem; border-radius: 0.25rem; font-size: 0.85rem; }
"""

_JS = """
function toggleTheme() {
  const root = document.documentElement;
  const current = root.getAttribute('data-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  root.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
}
"""


class HTMLReporter(AbstractReporter):
    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = self._render(assessment)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _render(self, assessment: Assessment) -> str:
        stats = assessment.stats
        parts: list[str] = []

        parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Assessment Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
""")
        # Hero
        parts.append(f"""
<div class="hero">
  <button class="theme-toggle" onclick="toggleTheme()">Toggle theme</button>
  <h1>Vulnerability Assessment Report</h1>
  <div class="meta">
    Generated: {_e(stats.generated_at)} &nbsp;|&nbsp;
    Targets: {stats.targets_scanned} &nbsp;|&nbsp;
    Findings: <strong>{stats.unique_findings}</strong> unique ({stats.total_findings} raw) &nbsp;|&nbsp;
    Duration: {stats.total_duration:.0f}s
  </div>
</div>
""")
        # Stats grid
        parts.append('<div class="stats-grid">')
        for sev in _SEV_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            color = _SEV_COLOR[sev]
            parts.append(
                f'<div class="stat-card"><div class="num" style="color:{color}">{count}</div>'
                f'<div class="label">{sev.value.capitalize()}</div></div>'
            )
        parts.append("</div>")

        # Executive summary
        summary = assessment.executive_summary or self._computed_summary(assessment)
        parts.append(f"""
<div class="section">
  <h2>Executive Summary</h2>
  <div class="exec-summary">{_e(summary)}</div>
</div>
""")

        # Clusters
        if assessment.clusters:
            parts.append('<div class="section"><h2>Vulnerability Clusters</h2>')
            for cluster in sorted(assessment.clusters, key=lambda c: _SEV_ORDER.index(c.severity)):
                color = _SEV_COLOR.get(cluster.severity, "#546e7a")
                badge = _badge(cluster.severity)
                parts.append(f"""
<div class="cluster-card" style="border-left:4px solid {color}">
  <h4>{badge} {_e(cluster.title)}</h4>
  <p>{_e(cluster.summary)}</p>
  {"<p><strong>Remediation:</strong> " + _e(cluster.shared_remediation) + "</p>" if cluster.shared_remediation else ""}
  {"<p><em>Tags: " + _e(", ".join(cluster.tags)) + "</em></p>" if cluster.tags else ""}
</div>
""")
            parts.append("</div>")

        # Per-target findings
        parts.append('<div class="section"><h2>Findings</h2>')
        by_target: dict[str, list[ScanResult]] = defaultdict(list)
        for r in assessment.results:
            by_target[r.target].append(r)

        for target in sorted(by_target):
            target_results = by_target[target]
            raw_pairs: list[tuple[str, Finding]] = []
            errors: list[tuple[str, str]] = []
            for r in sorted(target_results, key=lambda x: x.tool):
                if r.status == ScanStatus.SKIPPED and not r.findings:
                    continue
                if r.error and r.status != ScanStatus.SKIPPED:
                    errors.append((r.tool, r.error))
                for f in r.findings:
                    if f.false_positive:
                        continue
                    if not severity_passes(f.severity, self._min_severity):
                        continue
                    raw_pairs.append((r.tool, f))

            if not raw_pairs and not errors:
                continue

            # Deduplicate cross-tool findings before rendering
            groups = deduplicate_findings(raw_pairs)
            groups.sort(key=lambda g: _SEV_ORDER.index(g.finding.severity))

            parts.append(f"<details open><summary><code>{_e(target)}</code> — {len(groups)} finding(s)</summary>")

            for tool_name, err in errors:
                parts.append(f'<p style="color:var(--high)"><strong>{_e(tool_name)} error:</strong> {_e(err)}</p>')

            if groups:
                parts.append("""
<table>
<thead><tr>
  <th>Severity</th><th>Tool(s)</th><th>Title</th><th>CWE</th><th>Confidence</th><th>CVEs</th>
</tr></thead><tbody>
""")
                for g in groups:
                    f = g.finding
                    badge = _badge(f.severity)
                    cwes = _e(", ".join(f.cwe)) if f.cwe else "—"
                    cves = _e(", ".join(f.cve)) if f.cve else "—"
                    conf = _e(_CONF_LABEL.get(f.confidence, "—"))
                    tools_str = _e(", ".join(g.found_by))
                    parts.append(f"""
<tr>
  <td>{badge}</td>
  <td><code>{tools_str}</code></td>
  <td>
    <strong>{_e(f.title)}</strong>
    <div class="finding-detail">
      <p>{_e(f.description[:400])}</p>
      {self._mitigation_html(f)}
      {self._poc_html(f)}
    </div>
  </td>
  <td>{cwes}</td><td>{conf}</td><td>{cves}</td>
</tr>
""")
                parts.append("</tbody></table>")

            parts.append("</details>")

        parts.append("</div>")  # section

        # PoC assets
        if assessment.poc_asset_paths:
            parts.append('<div class="section"><h2>PoC Assets</h2><ul>')
            for path in assessment.poc_asset_paths:
                parts.append(f"<li><code>{_e(path)}</code></li>")
            parts.append("</ul></div>")

        parts.append(f"<script>{_JS}</script></div></body></html>")
        return "\n".join(parts)

    @staticmethod
    def _mitigation_html(f: Finding) -> str:
        parts = []
        if f.llm_notes:
            parts.append(f"<h5>Analyst notes</h5><p>{_e(f.llm_notes)}</p>")
        if f.exploitability:
            parts.append(f"<h5>Exploitability</h5><p>{_e(f.exploitability)}</p>")
        if f.mitigation:
            parts.append(f"<h5>Mitigation</h5><pre>{_e(f.mitigation)}</pre>")
        if f.remediation:
            parts.append(f"<h5>Remediation</h5><pre>{_e(f.remediation)}</pre>")
        return "".join(parts)

    @staticmethod
    def _poc_html(f: Finding) -> str:
        if not f.poc_ids:
            return ""
        ids = _e(", ".join(f.poc_ids))
        return f"<h5>PoC scripts</h5><p><code>{ids}</code></p>"

    @staticmethod
    def _computed_summary(assessment: Assessment) -> str:
        stats = assessment.stats
        if not stats.total_findings:
            return "No significant findings were identified during this assessment."
        sev_parts = []
        for sev in _SEV_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            if count:
                sev_parts.append(f"{count} {sev.value}")
        return (
            f"The assessment identified {stats.total_findings} finding(s) "
            f"across {stats.targets_scanned} target(s): {', '.join(sev_parts)}."
        )
