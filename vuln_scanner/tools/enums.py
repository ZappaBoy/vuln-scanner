"""Shared enums and severity helper for all tool modules."""
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class ScanMode(str, Enum):
    PARANOID = "paranoid"
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


class TargetType(str, Enum):
    HOST = "host"    # hostname (non-URL, non-IP)
    IP = "ip"        # single IPv4/IPv6 address
    CIDR = "cidr"    # IP range
    URL = "url"      # http/https URL
    PATH = "path"    # local filesystem path
    IMAGE = "image"  # container image reference (name:tag)
    REPO = "repo"    # git repository URL or path
    CLOUD = "cloud"  # cloud account/project (AWS ARN, GCP project, Azure subscription)


def _parse_severity(s: str) -> Severity:
    s = s.lower().strip()
    if s in ("critical", "c"):
        return Severity.CRITICAL
    if s in ("high", "h"):
        return Severity.HIGH
    if s in ("medium", "m", "warning", "warn", "moderate", "3"):
        return Severity.MEDIUM
    if s in ("low", "l", "1"):
        return Severity.LOW
    return Severity.INFO


def severity_passes(finding_sev: Severity, min_severity: str) -> bool:
    """Return True if finding_sev is at or above min_severity.

    min_severity="none" (the default) means every finding passes.
    Lower sort_order = higher severity, so passes when sort_order <= threshold.
    """
    if not min_severity or min_severity.lower() in ("none", ""):
        return True
    try:
        threshold = _parse_severity(min_severity)
    except Exception:
        return True
    return finding_sev.sort_order <= threshold.sort_order
