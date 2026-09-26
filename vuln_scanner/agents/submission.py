"""Bug-bounty submission report rendering.

Renders one submission-ready report per confirmed agent finding.  The generic
report layout lives in an external Jinja template (``templates/submission.md.jinja``);
a per-config ``template`` override is rendered with ``str.format`` fields so
simple custom one-liners keep working.  Written to ``<run_dir>/agent_submissions/``.
"""

import json
import logging
from collections import defaultdict
from pathlib import Path

from vuln_scanner.agents.models import AgentFinding, AgentReport, SubmissionConfig
from vuln_scanner.agents.templating import read_template_source, render_template

log = logging.getLogger(__name__)

SUBMISSION_TEMPLATE_NAME = "submission.md.jinja"
JSON_FORMAT = "json"
MARKDOWN_FORMAT = "markdown"
_SLUG_LIMIT = 50

# The built-in template source, exported for callers that want to inspect or
# clone the default layout.
DEFAULT_SUBMISSION_TEMPLATE = read_template_source(SUBMISSION_TEMPLATE_NAME)


def _fields(finding: AgentFinding) -> dict[str, str]:
    steps = "\n".join(f"{index}. {step}" for index, step in enumerate(finding.reproduction_steps, 1))
    references = "\n".join(f"- {reference}" for reference in finding.references)
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "vuln_class": ", ".join(finding.vuln_class) or "n/a",
        "affected_url": finding.affected_url or finding.target,
        "affected_param": finding.affected_param or "n/a",
        "cvss_score": "" if finding.cvss_score is None else str(finding.cvss_score),
        "cvss_vector": finding.cvss_vector,
        "confidence": finding.confidence,
        "discovered_by": finding.discovered_by,
        "verified": "yes" if finding.verified else "no",
        "summary": finding.summary or "n/a",
        "reproduction_steps": steps or "n/a",
        "request": finding.request or "n/a",
        "response": finding.response or "n/a",
        "oob_evidence": finding.oob_evidence or "n/a",
        "impact": finding.impact or "n/a",
        "remediation": finding.remediation or "n/a",
        "references": references or "n/a",
    }


def render_submission(finding: AgentFinding, template: str = "") -> str:
    """Render a single finding to a Markdown submission.

    A blank *template* renders the built-in Jinja template.  A custom *template*
    is rendered with ``str.format`` semantics; unknown placeholders resolve to an
    empty string rather than raising.
    """
    fields = _fields(finding)
    if not template:
        return render_template(SUBMISSION_TEMPLATE_NAME, **fields)
    try:
        return template.format_map(defaultdict(str, fields))
    except (ValueError, IndexError) as exc:  # malformed custom template
        log.warning("Submission template error: %s — using default.", exc)
        return render_template(SUBMISSION_TEMPLATE_NAME, **fields)


def _slug(text: str, limit: int = _SLUG_LIMIT) -> str:
    keep = [char if char.isalnum() else "-" for char in text.lower()]
    return "".join(keep).strip("-")[:limit] or "bug"


def write_submissions(
    reports: list[AgentReport],
    cfg: SubmissionConfig,
    out_dir: Path,
    default_formats: list[str] | None = None,
) -> list[str]:
    """Write submission files for every finding across *reports*.

    Returns the list of written file paths.
    """
    if not cfg.enabled:
        return []
    formats = [fmt.lower() for fmt in (cfg.formats or default_formats or [MARKDOWN_FORMAT])]
    written: list[str] = []
    index = 0
    for report in reports:
        for finding in report.findings:
            index += 1
            base = f"{index:03d}-{_slug(finding.title)}"
            for fmt in formats:
                try:
                    if fmt == JSON_FORMAT:
                        path = out_dir / f"{base}.json"
                        content = json.dumps(finding.model_dump(mode="json"), indent=2, ensure_ascii=False)
                    else:  # markdown (default) — html/pdf submissions fall back to md
                        path = out_dir / f"{base}.md"
                        content = render_submission(finding, cfg.template)
                    out_dir.mkdir(parents=True, exist_ok=True)
                    path.write_text(content, encoding="utf-8")
                    written.append(str(path))
                except OSError as exc:  # pragma: no cover - defensive
                    log.warning("Submission write failed for %s: %s", base, exc)
    if written:
        log.info("Wrote %d submission file(s) to %s", len(written), out_dir)
    return written
