"""Target classification — maps a target string to one or more TargetType values."""
import ipaddress
import os
import re

from vuln_scanner.tools.enums import TargetType

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_GIT_RE = re.compile(
    r"(\.git$|^git\+|^ssh://git@|^https?://github\.com|^https?://gitlab\.com)",
    re.IGNORECASE,
)
_IMAGE_RE = re.compile(r"^[a-z0-9_\-./]+:[a-zA-Z0-9_.\-]+$")

# Sentinel meaning "this tool accepts any target type"
_ALL_TARGET_TYPES: frozenset[TargetType] = frozenset(TargetType)


def classify_target(target: str) -> set[TargetType]:
    """Return the set of TargetTypes that describe *target*."""
    types: set[TargetType] = set()

    # Git repo (check before URL since git URLs can look like HTTPS)
    if _GIT_RE.search(target):
        types.add(TargetType.REPO)
        if _URL_RE.match(target):
            types.add(TargetType.URL)
        return types

    # HTTP/HTTPS URL
    if _URL_RE.match(target):
        types.add(TargetType.URL)
        return types

    # Local filesystem path
    if target.startswith(("/", "./", "../")):
        types.add(TargetType.PATH)
        return types

    # Relative path that actually exists
    if os.path.exists(target) and "/" in target:
        types.add(TargetType.PATH)
        return types

    # CIDR range
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            types.add(TargetType.CIDR)
            return types
        except ValueError:
            pass

    # IP address
    try:
        ipaddress.ip_address(target)
        types.add(TargetType.IP)
        return types
    except ValueError:
        pass

    # Default: treat as hostname
    types.add(TargetType.HOST)
    return types
