"""In-run typed asset store for the tool-chaining engine.

Tools declare what asset types they *produce* (discover) and *consume* (need
as input).  The orchestrator's wave scheduler seeds the store from the initial
targets, runs Wave 0 (tools with consumes=∅), collects produced assets, then
unlocks subsequent waves until a fixpoint is reached.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class AssetType(str, Enum):
    SUBDOMAIN = "subdomain"  # bare hostname (sub.example.com)
    LIVE_HOST = "live_host"  # confirmed live host (http/https probe passed)
    OPEN_PORT = "open_port"  # "host:port" or "host:port/service"
    URL = "url"  # http/https URL
    ENDPOINT = "endpoint"  # relative URL path (/api/v1/users)
    PARAM = "param"  # "target::param_name" or bare param name
    JS_URL = "js_url"  # JavaScript file URL
    TECH = "tech"  # technology fingerprint ("wordpress", "nginx:1.19")
    VHOST = "vhost"  # virtual hostname
    EMAIL = "email"  # email address
    BUCKET = "bucket"  # cloud storage bucket name/URL
    SECRET = "secret"  # credential / token / API key
    IP = "ip"  # discovered IP address


# Maps TargetType → AssetType for seeding the store from CLI targets.
_TARGET_TO_ASSET: dict[str, AssetType] = {
    "host": AssetType.SUBDOMAIN,
    "ip": AssetType.IP,
    "cidr": AssetType.IP,
    "url": AssetType.URL,
    "live_host": AssetType.LIVE_HOST,
}


@dataclass
class Asset:
    """A single typed value discovered during a scan."""

    type: AssetType
    value: str  # the actual discovered value
    source: str  # tool name that discovered it (or "seed" for initial targets)
    target: str  # original CLI target this asset was found for
    meta: dict = field(default_factory=dict)  # e.g. {"service": "https", "port": "443"}


class AssetStore:
    """Thread-safe accumulator of typed assets discovered during a run.

    Keyed by (type, value) so each unique value is stored once even if
    discovered by multiple tools.  Duplicate adds are silently ignored and
    return False; novel adds return True.
    """

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()  # (type.value, value)
        self._all: list[Asset] = []
        self._by_type: dict[str, list[Asset]] = {}
        self._lock = threading.Lock()

    # ── Seeding ──────────────────────────────────────────────────────────────

    def seed_from_targets(self, targets: list[str]) -> None:
        """Populate initial assets from the CLI target list."""
        from vuln_scanner.tools.target import classify_target

        for t in targets:
            for tt in classify_target(t):
                asset_type = _TARGET_TO_ASSET.get(tt.value)
                if asset_type:
                    self.add(Asset(type=asset_type, value=t, source="seed", target=t))
            # Also seed URL targets as LIVE_HOST when they look like live web targets
            if t.startswith(("http://", "https://")):
                self.add(Asset(type=AssetType.LIVE_HOST, value=t, source="seed", target=t))

    # ── Mutation ─────────────────────────────────────────────────────────────

    def add(self, asset: Asset) -> bool:
        """Add an asset.  Returns True if it was new (not a duplicate)."""
        key = (asset.type.value, asset.value.lower())
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._all.append(asset)
            self._by_type.setdefault(asset.type.value, []).append(asset)
            return True

    def add_many(self, assets: list[Asset]) -> int:
        """Add multiple assets.  Returns count of novel additions."""
        return sum(1 for a in assets if self.add(a))

    # ── Querying ─────────────────────────────────────────────────────────────

    def get(self, asset_type: AssetType) -> list[Asset]:
        """Return all assets of the given type."""
        with self._lock:
            return list(self._by_type.get(asset_type.value, []))

    def get_values(self, asset_type: AssetType) -> set[str]:
        """Return the set of values for the given type (lowercased)."""
        with self._lock:
            return {a.value for a in self._by_type.get(asset_type.value, [])}

    def new_since(
        self,
        asset_type: AssetType,
        already_seen: set[str],
    ) -> list[Asset]:
        """Assets of *asset_type* whose values are not in *already_seen*."""
        with self._lock:
            return [a for a in self._by_type.get(asset_type.value, []) if a.value.lower() not in already_seen]

    def has_any(self, *types: AssetType) -> bool:
        """True if the store contains at least one asset of any of *types*."""
        with self._lock:
            return any(t.value in self._by_type for t in types)

    @property
    def total(self) -> int:
        with self._lock:
            return len(self._all)
