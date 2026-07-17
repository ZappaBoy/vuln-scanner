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
# Cloud target patterns
_AWS_ARN_RE = re.compile(r"^arn:aws(-[a-z]+)*:", re.IGNORECASE)
_CLOUD_PREFIX_RE = re.compile(r"^(aws|gcp|azure):", re.IGNORECASE)
_GCP_PROJECT_RE = re.compile(r"^projects/[a-z][a-z0-9\-]+$", re.IGNORECASE)
_AZURE_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# Sentinel meaning "this tool accepts any target type"
_ALL_TARGET_TYPES: frozenset[TargetType] = frozenset(TargetType)


def classify_target(target: str) -> set[TargetType]:
    """Return the set of TargetTypes that describe *target*."""
    types: set[TargetType] = set()

    # Cloud account / project / ARN (check before everything else)
    if _AWS_ARN_RE.match(target) or _CLOUD_PREFIX_RE.match(target):
        types.add(TargetType.CLOUD)
        return types
    if _GCP_PROJECT_RE.match(target):
        types.add(TargetType.CLOUD)
        return types
    # Azure subscription UUID (bare UUID not starting with http)
    if _AZURE_UUID_RE.match(target):
        types.add(TargetType.CLOUD)
        return types

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
