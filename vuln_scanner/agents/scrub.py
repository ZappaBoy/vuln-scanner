"""Secret scrubbing for agent output before it reaches reports/submissions.

Exploited or probed targets can leak credentials into agent stdout, evidence,
and summaries.  Redact common secret shapes so they are not persisted in a
report that may later be shared.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vuln_scanner.agents.models import AgentReport

REDACTION = "[REDACTED]"

PRIVATE_KEY_PATTERN = (
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
)
AWS_ACCESS_KEY_PATTERN = r"\bAKIA[0-9A-Z]{16}\b"
AWS_TEMP_KEY_PATTERN = r"\bASIA[0-9A-Z]{16}\b"
GITHUB_TOKEN_PATTERN = r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"
SLACK_TOKEN_PATTERN = r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
OPENAI_KEY_PATTERN = r"\bsk-[A-Za-z0-9]{20,}\b"
JWT_PATTERN = r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
KEYED_SECRET_PATTERN = (
    r"(?:password|passwd|pwd|secret|api[_-]?key|token|authorization)"
    r"\s*[=:]\s*[\"']?([^\s\"'&]{6,})"
)

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        PRIVATE_KEY_PATTERN,
        AWS_ACCESS_KEY_PATTERN,
        AWS_TEMP_KEY_PATTERN,
        GITHUB_TOKEN_PATTERN,
        SLACK_TOKEN_PATTERN,
        OPENAI_KEY_PATTERN,
        JWT_PATTERN,
        KEYED_SECRET_PATTERN,
    )
]


def scrub_text(text: str) -> str:
    """Redact secret-shaped substrings in *text*."""
    if not text:
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    return redacted


# Backwards-compatible alias for the plain text scrubber.
scrub = scrub_text


def scrub_report(report: "AgentReport") -> "AgentReport":
    """Scrub every free-text field of an ``AgentReport`` in place. Returns it."""
    report.scrub_secrets()
    return report
