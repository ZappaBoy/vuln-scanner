"""Shared safety guards for the agentic layer.

These are the hard, in-code controls that sit in front of every agent action:
container gate, denylist, and host extraction for scope validation.  Prompts
are advisory; these are not.
"""

import ipaddress
import os
import re
import unicodedata

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
# Bracketed IPv6 authority as it appears in URLs / host:port, e.g. "[2001:db8::1]:443".
_IPV6_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:]+)\]")
# The three Unicode label separators IDNA treats as a dot (RFC 3490).  Mapping
# them to '.' stops a homoglyph host like "evil。com" from evading the
# ASCII-only host regexes above.
_IDNA_DOT_MAP = {ord("。"): ".", ord("．"): ".", ord("｡"): "."}


def _normalize_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value).translate(_IDNA_DOT_MAP)


def _is_ipv6(token: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(token), ipaddress.IPv6Address)
    except ValueError:
        return False


def extract_hosts(*values: str) -> set[str]:
    """Extract candidate hostnames / IPs from arbitrary text (argv, code, target).

    Best-effort: pulls hosts out of URLs, ``host:port`` tokens, bare domains,
    and IPv4/IPv6 literals so each can be scope-checked before an action runs.
    Input is Unicode-normalized first so homoglyph host separators cannot hide a
    domain from the ASCII host regexes.  This is deliberately conservative for
    single-label hosts (e.g. ``localhost``): those are only rejected by the
    fail-closed :meth:`AgentDeps.assert_target_in_scope` path, not here, so that
    free-text argv / code is not littered with false host matches.
    """
    hosts: set[str] = set()
    for value in values:
        if not value:
            continue
        value = _normalize_text(value)
        for m in _URL_RE.finditer(value):
            hosts.add(_strip_port(m.group(1)))
        for m in _HOSTPORT_RE.finditer(value):
            hosts.add(_strip_port(m.group(1)))
        for m in _IPV6_BRACKET_RE.finditer(value):
            if _is_ipv6(m.group(1)):
                hosts.add(m.group(1).lower())
        for token in re.split(r"[\s'\"]+", value):
            token = token.strip().split("/")[0]
            if token.count(":") >= 2 and _is_ipv6(token):
                hosts.add(token.lower())
    return {h for h in hosts if h}


def canonical_host(value: str) -> str:
    """Reduce a single URL / ``host:port`` / ``[ipv6]`` token to a bare host.

    Unlike :func:`extract_hosts`, this treats *value* as one explicit host the
    caller means to reach, so it also returns single-label hosts (``localhost``)
    that ``extract_hosts`` intentionally ignores.  Returns ``""`` when nothing
    host-like remains (e.g. a bare path).
    """
    host = _normalize_text(value).strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0]
    if host.startswith("["):  # [ipv6] or [ipv6]:port
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # host:port (not bare IPv6, which has >1 colon)
        left, right = host.split(":", 1)
        if right.isdigit():
            host = left
    return host.rstrip(".")


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
