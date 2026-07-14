from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.base import Finding, ScanResult, ScanStatus, Severity

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

        # Group results and findings by target host
        by_target: dict[str, list[ScanResult]] = defaultdict(list)
        for r in results:
            by_target[r.target].append(r)

        total_findings = sum(len(r.findings) for r in results)
        lines: list[str] = []

        lines += [
            "# Vulnerability Scan Report",
            "",
            f"**Generated:** {now}",
            f"**Hosts scanned:** {len(by_target)}",
            f"**Total findings:** {total_findings}",
            "",
        ]

        # --- summary table: only tools that produced findings or errors ---
        lines += [
            "## Summary",
            "",
            "| Host | Tool | Status | Findings | Duration |",
            "|------|------|--------|----------|----------|",
        ]
        for target in sorted(by_target):
            for r in sorted(by_target[target], key=lambda x: x.tool):
                if not r.findings and not r.error:
                    continue
                status_icon = "✅" if r.status == ScanStatus.SUCCESS else "❌"
                lines.append(
                    f"| `{target}` | `{r.tool}` | {status_icon} {r.status.value} "
                    f"| {len(r.findings)} | {r.duration:.1f}s |"
                )
        lines.append("")

        # --- findings grouped by host: skip hosts with nothing to report ---
        lines += ["## Findings", ""]

        for target in sorted(by_target):
            target_results = by_target[target]

            # Collect findings and errors for this host
            all_findings: list[tuple[str, Finding]] = []
            errors: list[tuple[str, str]] = []
            for r in sorted(target_results, key=lambda x: x.tool):
                if r.error:
                    errors.append((r.tool, r.error))
                for f in r.findings:
                    all_findings.append((r.tool, f))

            if not all_findings and not errors:
                continue

            lines += [f"### {target}", ""]

            for tool_name, err in errors:
                lines += [f"> **{tool_name} error:** {err}", ""]

            if not all_findings:
                continue

            all_findings.sort(key=lambda x: _SEVERITY_ORDER.index(x[1].severity))

            lines += [
                "| Severity | Tool | Title | Description | CVEs |",
                "|----------|------|-------|-------------|------|",
            ]
            for tool_name, f in all_findings:
                emoji = _SEVERITY_EMOJI.get(f.severity, "")
                cves = ", ".join(f.cve) if f.cve else "—"
                desc = f.description.replace("|", "\\|").replace("\n", " ")
                title = f.title.replace("|", "\\|")
                lines.append(
                    f"| {emoji} {f.severity.value.upper()} | `{tool_name}` "
                    f"| {title} | {desc} | {cves} |"
                )
            lines.append("")

        return lines
