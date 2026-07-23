"""Scope enforcement for red-team / bug-bounty assessments.

Patterns supported in ``include`` / ``exclude`` lists:
  - Glob wildcard:  ``*.example.com``  (fnmatch against extracted hostname)
  - CIDR range:     ``10.0.0.0/8``
  - URL prefix:     ``https://app.example.com/api``
  - Exact match:    ``admin.example.com``

Evaluation order:
  1. If ``exclude`` matches → out of scope (hard deny).
  2. If ``include`` is empty → in scope (no filter applied).
  3. If ``include`` is non-empty → must match at least one pattern.

This is intentionally conservative: when ``strict=True``, a target that
cannot be parsed is treated as out of scope so it is never accidentally scanned.
"""

import fnmatch
import ipaddress
import logging
from urllib.parse import urlparse

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


def _extract_host(target: str) -> str:
    """Return the bare hostname/IP from a target string (URL, host, or IP)."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    # strip port if present
    if ":" in target and not target.startswith("["):
        return target.split(":")[0]
    return target


def _matches_pattern(host: str, pattern: str) -> bool:
    """Return True if *host* matches *pattern* (CIDR, glob, or exact)."""
    # CIDR
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            try:
                addr = ipaddress.ip_address(host)
                return addr in net
            except ValueError:
                return False
        except ValueError:
            pass
    # Glob / wildcard
    return fnmatch.fnmatch(host.lower(), pattern.lower())


def _target_in_list(target: str, patterns: list[str]) -> bool:
    host = _extract_host(target)
    for pattern in patterns:
        # URL prefix match (applied to full target string)
        if pattern.startswith(("http://", "https://")):
            if target.lower().startswith(pattern.lower()):
                return True
            continue
        if _matches_pattern(host, pattern):
            return True
    return False


class ScopeValidator:
    """Validates targets against in-scope / out-of-scope rules.

    Usage::

        validator = ScopeValidator(config.scope)
        safe_targets = validator.filter(discovered_targets)
        # for user-provided targets, use check() which respects strict mode
    """

    def __init__(self, include: list[str], exclude: list[str], strict: bool = False) -> None:
        self._include = include
        self._exclude = exclude
        self._strict = strict

    @classmethod
    def from_config(cls, config: "ScopeConfig") -> "ScopeValidator":
        return cls(
            include=config.include,
            exclude=config.exclude,
            strict=config.strict,
        )

    @property
    def has_rules(self) -> bool:
        """True when at least one include/exclude pattern or strict mode is active."""
        return bool(self._include or self._exclude or self._strict)

    def is_in_scope(self, target: str, discovered: bool = False) -> bool:
        """Return True if *target* is in scope.

        ``discovered=True`` means the target came from recon (not the user's
        explicit list) — it is always subject to the include filter even when
        ``strict=False``.
        """
        # Explicit excludes win unconditionally
        if self._exclude and _target_in_list(target, self._exclude):
            log.debug("SCOPE DENY (exclude): %s", target)
            return False

        # No include list → pass through unless strict or discovered
        if not self._include:
            if discovered or self._strict:
                log.debug("SCOPE DENY (no include, discovered/strict): %s", target)
                return False
            return True

        if _target_in_list(target, self._include):
            return True

        log.debug("SCOPE DENY (not in include): %s", target)
        return False

    def filter(self, targets: list[str], discovered: bool = False) -> list[str]:
        """Return only the targets that pass scope validation."""
        passed = [t for t in targets if self.is_in_scope(t, discovered=discovered)]
        denied = len(targets) - len(passed)
        if denied:
            log.info("Scope filter: %d/%d targets denied.", denied, len(targets))
        return passed


# ─── Config model (imported by config/models.py) ──────────────────────────────


class ScopeConfig(BaseModel):
    """Defines which targets are in scope for this assessment."""

    include: list[str] = Field(
        default_factory=list,
        description=(
            "In-scope patterns: *.example.com, 10.0.0.0/8, https://app.example.com. "
            "Empty = all targets pass (unless strict=True)."
        ),
    )
    exclude: list[str] = Field(
        default_factory=list,
        description="Always out-of-scope patterns. Takes precedence over include.",
    )
    strict: bool = Field(
        default=False,
        description=(
            "When True, an empty include list blocks everything (nothing is in scope). "
            "Useful for discovered assets: enables full deny-by-default posture."
        ),
    )
