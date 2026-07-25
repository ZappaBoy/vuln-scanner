"""Secret scrubbing for agent output before it reaches reports/submissions.

Exploited or probed targets can leak credentials into agent stdout, evidence,
and summaries.  Redact common secret shapes so they are not persisted in a
report that may later be shared.
"""

import re

from vuln_scanner.agents.models import AgentReport

_REDACTION = "[REDACTED]"

_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in [
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        r"\bAKIA[0-9A-Z]{16}\b",  # AWS access key id
        r"\bASIA[0-9A-Z]{16}\b",  # AWS temporary key id
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",  # GitHub tokens
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",  # Slack tokens
        r"\bsk-[A-Za-z0-9]{20,}\b",  # OpenAI-style keys
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",  # JWT
        r"(?:password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[=:]\s*[\"']?([^\s\"'&]{6,})",
    ]
]


def scrub(text: str) -> str:
    """Redact secret-shaped substrings in *text*."""
    if not text:
        return text
    out = text
    for pat in _PATTERNS:
        out = pat.sub(_REDACTION, out)
    return out


def scrub_report(report: AgentReport) -> AgentReport:
    """Scrub every free-text field of an AgentReport in place. Returns it."""
    report.summary = scrub(report.summary)
    report.exploit_plan = [scrub(s) for s in report.exploit_plan]
    for f in report.findings:
        f.summary = scrub(f.summary)
        f.request = scrub(f.request)
        f.response = scrub(f.response)
        f.oob_evidence = scrub(f.oob_evidence)
        f.impact = scrub(f.impact)
        f.reproduction_steps = [scrub(s) for s in f.reproduction_steps]
    for p in report.pocs:
        p.evidence = scrub(p.evidence)
        p.command = scrub(p.command)
    return report
