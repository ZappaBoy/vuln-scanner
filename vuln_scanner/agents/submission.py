"""Bug-bounty submission report rendering.

Renders one submission-ready report per confirmed agent finding, from an
overridable template, in the configured formats (markdown/json).  Written to
``<run_dir>/agent_submissions/``.
"""

import json
import logging
from collections import defaultdict
from pathlib import Path

from vuln_scanner.agents.models import AgentFinding, AgentReport, SubmissionConfig

log = logging.getLogger(__name__)

DEFAULT_SUBMISSION_TEMPLATE = """\
# {title}

- **Severity:** {severity}
- **Vulnerability class:** {vuln_class}
- **Affected URL:** {affected_url}
- **Affected parameter:** {affected_param}
- **CVSS:** {cvss_score} {cvss_vector}
- **Confidence:** {confidence}
- **Discovered by:** {discovered_by}
- **Verified:** {verified}

## Summary
{summary}

## Steps to Reproduce
{reproduction_steps}

## Proof / Evidence
### Request
```
{request}
```
### Response
```
{response}
```
### Out-of-band interaction
{oob_evidence}

## Impact
{impact}

## Remediation
{remediation}

## References
{references}
"""


def _fields(finding: AgentFinding) -> dict[str, str]:
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(finding.reproduction_steps, 1))
    refs = "\n".join(f"- {r}" for r in finding.references)
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
        "references": refs or "n/a",
    }


def render_submission(finding: AgentFinding, template: str = "") -> str:
    """Render a single finding to a Markdown submission using *template*.

    A blank *template* uses the built-in default.  Unknown placeholders in a
    custom template resolve to an empty string rather than raising.
    """
    tmpl = template or DEFAULT_SUBMISSION_TEMPLATE
    fields: dict[str, str] = defaultdict(str, _fields(finding))
    try:
        return tmpl.format_map(fields)
    except (ValueError, IndexError) as exc:  # malformed custom template
        log.warning("Submission template error: %s — using default.", exc)
        return DEFAULT_SUBMISSION_TEMPLATE.format_map(fields)


def _slug(text: str, limit: int = 50) -> str:
    keep = [c if c.isalnum() else "-" for c in text.lower()]
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
    formats = [f.lower() for f in (cfg.formats or default_formats or ["markdown"])]
    written: list[str] = []
    idx = 0
    for report in reports:
        for finding in report.findings:
            idx += 1
            base = f"{idx:03d}-{_slug(finding.title)}"
            for fmt in formats:
                try:
                    if fmt == "json":
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
