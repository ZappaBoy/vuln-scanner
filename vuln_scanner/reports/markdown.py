from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.base import ScanResult, ScanStatus, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class MarkdownReporter(AbstractReporter):
    def generate(self, results: list[ScanResult], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines = self._render(results)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _render(self, results: list[ScanResult]) -> list[str]:
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: list[str] = []

        lines += [
            "# Vulnerability Scan Report",
            "",
            f"**Generated:** {now}",
            f"**Total scans:** {len(results)}",
            f"**Total findings:** {sum(len(r.findings) for r in results)}",
            "",
        ]

        # --- summary table ---
        lines += [
            "## Summary",
            "",
            "| Tool | Target | Status | Findings | Duration |",
            "|------|--------|--------|----------|----------|",
        ]
        for r in sorted(results, key=lambda x: (x.tool, x.target)):
            status_icon = "✅" if r.status == ScanStatus.SUCCESS else "❌"
            lines.append(
                f"| `{r.tool}` | `{r.target}` | {status_icon} {r.status.value} "
                f"| {len(r.findings)} | {r.duration:.1f}s |"
            )
        lines.append("")

        # --- findings by result ---
        lines += ["## Findings", ""]

        all_results_sorted = sorted(results, key=lambda x: (x.tool, x.target))
        for r in all_results_sorted:
            lines += [
                f"### {r.tool} → `{r.target}`",
                "",
            ]

            if r.error:
                lines += [f"> **Error:** {r.error}", ""]

            if not r.findings:
                lines += ["*No findings.*", ""]
                continue

            sorted_findings = sorted(r.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))

            lines += [
                "| Severity | Title | Description | CVEs |",
                "|----------|-------|-------------|------|",
            ]
            for f in sorted_findings:
                emoji = _SEVERITY_EMOJI.get(f.severity, "")
                cves = ", ".join(f.cve) if f.cve else "—"
                desc = f.description.replace("|", "\\|").replace("\n", " ")
                title = f.title.replace("|", "\\|")
                lines.append(
                    f"| {emoji} {f.severity.value.upper()} | {title} | {desc} | {cves} |"
                )
            lines.append("")

        return lines
