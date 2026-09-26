"""Independent verification pass — re-run a bug's PoC before it is submission-ready.

Re-executes each recorded PoC script once in the sandbox; if it reproduces
(expected indicator observed, or clean exit when no indicator was declared) the
matching finding is marked ``verified``.  Container-only; best-effort.
"""

import logging
from pathlib import Path

from vuln_scanner.agents.guards import is_in_container
from vuln_scanner.agents.models import AgentReport, SandboxConfig
from vuln_scanner.agents.sandbox import run_code_sandboxed

log = logging.getLogger(__name__)


def verify_report(
    report: AgentReport,
    *,
    sandbox: SandboxConfig,
    code_languages: list[str],
) -> int:
    """Re-run PoCs to independently confirm findings. Returns count verified."""
    if not is_in_container():
        return 0

    verified = 0
    for poc in report.pocs:
        if not poc.script_path:
            continue
        try:
            code = Path(poc.script_path).read_text(encoding="utf-8")
        except OSError:
            continue

        result = run_code_sandboxed(
            poc.language,
            code,
            sandbox=sandbox,
            allowed_languages=code_languages,
        )
        if result.blocked:
            continue

        combined = f"{result.stdout}\n{result.stderr}"
        if poc.expected_indicator:
            reproduced = poc.expected_indicator.lower() in combined.lower()
        else:
            reproduced = result.exit_code == 0

        if reproduced:
            poc.verdict = "confirmed"
            poc.evidence = (poc.evidence + "\n[verification re-run]\n" + combined).strip()
            for f in report.findings:
                if f.title == poc.finding_title and not f.verified:
                    f.verified = True
                    verified += 1

    if verified:
        log.info("Verification: independently confirmed %d finding(s) for %s.", verified, report.agent_name)
    return verified
