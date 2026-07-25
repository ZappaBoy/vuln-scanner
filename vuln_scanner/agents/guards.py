"""Shared safety guards for the agentic layer.

These are the hard, in-code controls that sit in front of every agent action:
container gate, denylist, and host extraction for scope validation.  Prompts
are advisory; these are not.
"""

import ipaddress
import os
import re

# Reuse the PoC denylist as the base and extend it with agent-specific patterns.
from vuln_scanner.poc.generator import _DENYLIST_RE as _POC_DENYLIST_RE

_CONTAINER_MARKER = "VS_IN_CONTAINER"


def is_in_container() -> bool:
    """True only inside the Docker image (VS_IN_CONTAINER=1)."""
    return os.environ.get(_CONTAINER_MARKER, "").strip() == "1"


# ── Denylist (argv + code) ────────────────────────────────────────────────────

# Additional destructive/anti-forensic patterns beyond the PoC generator's list.
_AGENT_EXTRA_RE = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in [
        r"\bmkfs\b",  # any filesystem format
        r"\bwipefs\b",  # wipe filesystem signatures
        r">\s*/dev/sd[a-z]",  # write to raw disk
        r"\bfdisk\b|\bparted\b|\bgdisk\b",  # partition tables
        r"\buserdel\b|\bgroupdel\b",  # delete accounts
        r"\bchpasswd\b|\bpasswd\s+root\b",  # credential tampering
        r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:",  # classic fork bomb :(){ :|: }
        r"\bhistory\s+-c\b|rm\s+.*\.bash_history",  # anti-forensics
        r"\bnc\b.*-e\b|\bncat\b.*-e\b|/dev/tcp/",  # reverse shells off-box
        r"\bcrontab\b\s+-r",  # wipe cron
        r"\bufw\s+disable\b|iptables\s+-F",  # disable firewalling
    ]
]

_ALL_DENYLIST_RE = list(_POC_DENYLIST_RE) + _AGENT_EXTRA_RE


def denylist_check(text: str) -> tuple[bool, str]:
    """Return (safe, reason).  ``safe`` is False on any destructive pattern."""
    for pattern in _ALL_DENYLIST_RE:
        m = pattern.search(text or "")
        if m:
            return False, f"Denylist match: {m.group()!r}"
    return True, ""


# ── Host extraction (for scope validation) ────────────────────────────────────

_URL_RE = re.compile(r"\bhttps?://([^\s/\\:'\"]+)", re.IGNORECASE)
# host:port or bare host token — conservative; used to catch args like
# "example.com:445" or "10.0.0.5".
_HOSTPORT_RE = re.compile(
    r"\b((?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b"
)


def extract_hosts(*values: str) -> set[str]:
    """Extract candidate hostnames / IPs from arbitrary text (argv, code, target).

    Best-effort: pulls hosts out of URLs, ``host:port`` tokens, bare domains and
    IPv4 literals so each can be scope-checked before an action runs.
    """
    hosts: set[str] = set()
    for value in values:
        if not value:
            continue
        for m in _URL_RE.finditer(value):
            hosts.add(_strip_port(m.group(1)))
        for m in _HOSTPORT_RE.finditer(value):
            hosts.add(_strip_port(m.group(1)))
    return {h for h in hosts if h}


def _strip_port(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    # Strip a trailing :port (but keep bare IPv6 out of scope — rare here).
    if host.count(":") == 1:
        left, right = host.split(":", 1)
        if right.isdigit():
            return left
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
