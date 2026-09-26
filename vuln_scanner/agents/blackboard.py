"""EngagementState — the shared blackboard for a multi-agent engagement.

A single, thread-safe, in-process store that every agent in one engagement
reads from and writes to: discovered assets, cross-agent findings, and captured
credentials.  It is the substrate that turns a set of isolated single-shot
agents into a collaborating team — one agent's discovery becomes visible to the
next without being forced through an LLM context window.

Authoritative state lives in memory: agents run as asyncio tasks / threads in a
single process, so a lock is sufficient and no external datastore is required.
Every mutation is additionally appended to a best-effort JSONL event log at
``<run_dir>/blackboard/events.jsonl`` for post-hoc audit and debugging; a
log-write failure never affects in-memory state.

Security invariants:

- The blackboard stores *data*, never trust.  A host recorded here is NOT
  implicitly in scope — every host-touching tool re-validates scope at the
  point of use (see :mod:`vuln_scanner.agents.agent_tools`).  This keeps the
  blackboard from becoming a scope-bypass channel between agents.
- Captured credentials are engagement-private: available to agents during the
  run, but callers must keep them out of ``AgentReport`` summaries and rely on
  :mod:`vuln_scanner.agents.scrub` before any report leaves the process.
"""

import json
import logging
import threading
import time
from pathlib import Path

from pydantic import BaseModel, Field

from vuln_scanner.agents.models import AgentFinding

log = logging.getLogger(__name__)

_MAX_ASSETS = 5000
_MAX_FINDINGS = 2000
_MAX_CREDENTIALS = 1000


class SharedAsset(BaseModel):
    """An asset one agent discovered and published for the others."""

    type: str  # free-form asset class (e.g. "url", "subdomain", "endpoint", "param")
    value: str
    source: str = ""  # agent name / tool that surfaced it
    ts: float = Field(default_factory=time.time)


class Credential(BaseModel):
    """A secret captured during the engagement (loot).

    Engagement-private: never emit these into a report without scrubbing.
    """

    kind: str  # "password" | "hash" | "token" | "key" | "cookie" | ...
    username: str = ""
    secret: str = ""
    host: str = ""
    source: str = ""  # agent name that captured it
    ts: float = Field(default_factory=time.time)


def _asset_key(asset_type: str, value: str) -> str:
    return f"{asset_type.strip().lower()}:{value.strip()}"


def _finding_key(finding: AgentFinding) -> str:
    return f"{finding.title.strip().lower()}|{(finding.affected_url or finding.target).strip().lower()}"


def _credential_key(credential: Credential) -> str:
    return f"{credential.kind}|{credential.username}|{credential.host}|{credential.secret}".lower()


class EngagementState:
    """Thread-safe shared state for all agents in one engagement.

    All public methods are safe to call from multiple threads / concurrently
    scheduled coroutines.  Mutating methods return ``True`` when the item was
    newly added and ``False`` when it was a duplicate or a cap was hit, so a
    caller can tell a novel discovery from a repeat.
    """

    def __init__(self, run_dir: Path | None = None) -> None:
        self._lock = threading.RLock()
        self._assets: dict[str, SharedAsset] = {}
        self._findings: dict[str, AgentFinding] = {}
        self._credentials: dict[str, Credential] = {}
        self._event_path: Path | None = None
        if run_dir is not None:
            blackboard_dir = Path(run_dir) / "blackboard"
            try:
                blackboard_dir.mkdir(parents=True, exist_ok=True)
                self._event_path = blackboard_dir / "events.jsonl"
            except OSError as exc:  # pragma: no cover - defensive
                log.warning("Blackboard event log unavailable: %s", exc)

    # ── Assets ────────────────────────────────────────────────────────────────

    def add_asset(self, asset_type: str, value: str, source: str = "") -> bool:
        value = (value or "").strip()
        if not value:
            return False
        key = _asset_key(asset_type, value)
        with self._lock:
            if key in self._assets or len(self._assets) >= _MAX_ASSETS:
                return False
            asset = SharedAsset(type=asset_type.strip().lower(), value=value, source=source)
            self._assets[key] = asset
        self._append_event("asset", asset.model_dump(mode="json"))
        return True

    def assets(self, asset_type: str = "") -> list[SharedAsset]:
        want = asset_type.strip().lower()
        with self._lock:
            items = list(self._assets.values())
        if want:
            items = [a for a in items if a.type == want]
        return sorted(items, key=lambda a: a.ts)

    # ── Findings ────────────────────────────────────────────────────────────────

    def add_finding(self, finding: AgentFinding) -> bool:
        key = _finding_key(finding)
        with self._lock:
            if key in self._findings or len(self._findings) >= _MAX_FINDINGS:
                return False
            self._findings[key] = finding
        self._append_event(
            "finding",
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "target": finding.affected_url or finding.target,
                "by": finding.discovered_by,
            },
        )
        return True

    def findings(self) -> list[AgentFinding]:
        with self._lock:
            return list(self._findings.values())

    # ── Credentials (loot) ──────────────────────────────────────────────────────

    def add_credential(self, credential: Credential) -> bool:
        key = _credential_key(credential)
        with self._lock:
            if key in self._credentials or len(self._credentials) >= _MAX_CREDENTIALS:
                return False
            self._credentials[key] = credential
        # The secret itself is never written to the event log — only its shape.
        self._append_event(
            "credential",
            {
                "kind": credential.kind,
                "username": credential.username,
                "host": credential.host,
                "source": credential.source,
            },
        )
        return True

    def credentials(self) -> list[Credential]:
        with self._lock:
            return list(self._credentials.values())

    # ── Summary ─────────────────────────────────────────────────────────────────

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "assets": len(self._assets),
                "findings": len(self._findings),
                "credentials": len(self._credentials),
            }

    # ── Persistence ───────────────────────────────────────────────────────────

    def _append_event(self, kind: str, payload: dict) -> None:
        if self._event_path is None:
            return
        record = {"ts": time.time(), "kind": kind, "data": payload}
        try:
            with self._lock:
                with open(self._event_path, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as exc:  # pragma: no cover - defensive
            log.warning("Blackboard event write failed: %s", exc)
