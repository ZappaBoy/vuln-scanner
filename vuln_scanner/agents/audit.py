"""Append-only JSONL audit log for agent actions.

Every guarded agent action (tool exec, code run, OOB call, scope decision) is
recorded here so a bug submission is reproducible and the report can link the
exact command trail.  One file per agent: ``<log_dir>/<agent>.jsonl``.
"""

import json
import logging
import threading
import time
from pathlib import Path

from vuln_scanner.agents.models import ActionRecord

log = logging.getLogger(__name__)

_MAX_FIELD = 4000  # truncate long stdout/stderr/code fields in the log


def _truncate(value: str) -> str:
    if value and len(value) > _MAX_FIELD:
        return value[:_MAX_FIELD] + f"\n… [{len(value) - _MAX_FIELD} chars truncated]"
    return value


class ActionLog:
    """Thread-safe append-only JSONL writer for one agent."""

    def __init__(self, log_dir: Path, agent_name: str) -> None:
        self._lock = threading.Lock()
        self._agent = agent_name
        log_dir.mkdir(parents=True, exist_ok=True)
        safe = agent_name.replace("/", "_").replace(" ", "_")
        self.path = log_dir / f"{safe}.jsonl"
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def record(self, action: str, **fields: object) -> None:
        """Append one action record.

        String fields are truncated to keep the log bounded.  Never raises —
        an audit-write failure must not crash an agent run.
        """
        record = ActionRecord(ts=time.time(), agent=self._agent, action=action, **fields)
        data = record.model_dump()
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = _truncate(value)
        line = json.dumps(data, ensure_ascii=False, default=str)
        try:
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._count += 1
        except OSError as exc:  # pragma: no cover - defensive
            log.warning("Audit log write failed for %s: %s", self._agent, exc)
