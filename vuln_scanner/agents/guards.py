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

CONTAINER_MARKER = "VS_IN_CONTAINER"
CONTAINER_MARKER_VALUE = "1"

# ── Denylist patterns (destructive / anti-forensic argv + code) ───────────────

FILESYSTEM_FORMAT_PATTERN = r"\bmkfs\b"
FILESYSTEM_WIPE_PATTERN = r"\bwipefs\b"
RAW_DISK_WRITE_PATTERN = r">\s*/dev/sd[a-z]"
PARTITION_TABLE_PATTERN = r"\bfdisk\b|\bparted\b|\bgdisk\b"
ACCOUNT_DELETE_PATTERN = r"\buserdel\b|\bgroupdel\b"
CREDENTIAL_TAMPER_PATTERN = r"\bchpasswd\b|\bpasswd\s+root\b"
FORK_BOMB_PATTERN = r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:"
ANTI_FORENSICS_PATTERN = r"\bhistory\s+-c\b|rm\s+.*\.bash_history"
REVERSE_SHELL_PATTERN = r"\bnc\b.*-e\b|\bncat\b.*-e\b|/dev/tcp/"
CRON_WIPE_PATTERN = r"\bcrontab\b\s+-r"
FIREWALL_DISABLE_PATTERN = r"\bufw\s+disable\b|iptables\s+-F"

_AGENT_DENYLIST_PATTERNS = (
    FILESYSTEM_FORMAT_PATTERN,
    FILESYSTEM_WIPE_PATTERN,
    RAW_DISK_WRITE_PATTERN,
    PARTITION_TABLE_PATTERN,
    ACCOUNT_DELETE_PATTERN,
    CREDENTIAL_TAMPER_PATTERN,
    FORK_BOMB_PATTERN,
    ANTI_FORENSICS_PATTERN,
    REVERSE_SHELL_PATTERN,
    CRON_WIPE_PATTERN,
    FIREWALL_DISABLE_PATTERN,
)

_AGENT_EXTRA_RE = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in _AGENT_DENYLIST_PATTERNS]

_ALL_DENYLIST_RE = list(_POC_DENYLIST_RE) + _AGENT_EXTRA_RE

# ── Host extraction patterns (for scope validation) ───────────────────────────

_URL_RE = re.compile(r"\bhttps?://([^\s/\\:'\"]+)", re.IGNORECASE)
_HOSTPORT_RE = re.compile(
    r"\b((?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b"
)


def is_in_container() -> bool:
    """True only inside the Docker image (``VS_IN_CONTAINER=1``)."""
    return os.environ.get(CONTAINER_MARKER, "").strip() == CONTAINER_MARKER_VALUE


def denylist_check(text: str) -> tuple[bool, str]:
    """Return ``(safe, reason)``.  ``safe`` is False on any destructive pattern."""
    for pattern in _ALL_DENYLIST_RE:
        match = pattern.search(text or "")
        if match:
            return False, f"Denylist match: {match.group()!r}"
    return True, ""


def extract_hosts(*values: str) -> set[str]:
    """Extract candidate hostnames / IPs from arbitrary text (argv, code, target).

    Best-effort: pulls hosts out of URLs, ``host:port`` tokens, bare domains and
    IPv4 literals so each can be scope-checked before an action runs.
    """
    hosts: set[str] = set()
    for value in values:
        if not value:
            continue
        for match in _URL_RE.finditer(value):
            hosts.add(_strip_port(match.group(1)))
        for match in _HOSTPORT_RE.finditer(value):
            hosts.add(_strip_port(match.group(1)))
    return {host for host in hosts if host}


def _strip_port(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    # A trailing :port is dropped; bare IPv6 is intentionally left out of scope.
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
