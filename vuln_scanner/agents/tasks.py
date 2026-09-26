"""Task queue for delegated multi-agent work.

A lead agent decomposes an objective into :class:`Task` items addressed to
specialist roles; specialist agents claim, execute, and complete them.  The
queue is the hand-off channel between agents and is thread-safe so it can be
driven by the concurrent supervisor.

Two caps are load-bearing security controls, not tuning knobs:

- ``max_tasks`` bounds the total number of tasks ever posted, so a
  misbehaving or adversarial agent cannot flood the queue and exhaust the
  token / compute budget of the whole engagement.
- ``max_depth`` bounds delegation recursion (a task posted while handling a
  task increments depth), so agents cannot spawn an unbounded delegation tree.

Both are enforced in :meth:`TaskQueue.post`; the tool layer never bypasses them.
"""

import threading
import time
from enum import Enum

from pydantic import BaseModel, Field


class TaskStatus(str, Enum):
    """Lifecycle of a delegated task.

    ``PENDING`` — posted, not yet claimed; ``CLAIMED`` — a specialist is working
    it; ``COMPLETED`` — finished with a result summary; ``FAILED`` — abandoned
    with a reason.
    """

    PENDING = "pending"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"


class Task(BaseModel):
    """A unit of work addressed to a specialist role."""

    id: str = Field(description="Stable task identifier, e.g. task-0001.")
    role: str = Field(description="Target specialist role name (see roles.py); empty means any.")
    objective: str = Field(description="What the specialist should accomplish.")
    target: str = Field("", description="Scope hint; re-validated against scope at execution time.")
    status: TaskStatus = Field(TaskStatus.PENDING, description="Current lifecycle status.")
    created_by: str = Field("", description="Agent name that posted the task.")
    claimed_by: str = Field("", description="Agent name that claimed the task.")
    result_summary: str = Field("", description="Result or failure reason once finished.")
    parent_id: str = Field("", description="Task being handled when this was posted (delegation edge).")
    depth: int = Field(0, description="Delegation depth; root tasks posted by the lead are depth 1.")
    ts: float = Field(default_factory=time.time, description="Unix timestamp when the task was posted.")


class TaskQueue:
    """Thread-safe queue of :class:`Task` items with delegation guardrails."""

    def __init__(self, max_tasks: int = 200, max_depth: int = 3) -> None:
        self._lock = threading.RLock()
        self._tasks: dict[str, Task] = {}
        self._posted_total = 0
        self._max_tasks = max_tasks
        self._max_depth = max_depth

    def post(
        self,
        role: str,
        objective: str,
        *,
        target: str = "",
        created_by: str = "",
        parent: Task | None = None,
    ) -> Task | None:
        """Post a new task.  Returns the task, or ``None`` if a cap blocked it.

        ``depth`` is derived from *parent*: a task posted while handling another
        is one level deeper.  Posting is refused once ``max_tasks`` have ever
        been posted or the derived depth would exceed ``max_depth``.
        """
        objective = (objective or "").strip()
        if not objective:
            return None
        depth = (parent.depth + 1) if parent is not None else 1
        with self._lock:
            if self._posted_total >= self._max_tasks:
                return None
            if depth > self._max_depth:
                return None
            self._posted_total += 1
            task_id = f"task-{self._posted_total:04d}"
            task = Task(
                id=task_id,
                role=role.strip(),
                objective=objective,
                target=target.strip(),
                created_by=created_by,
                parent_id=parent.id if parent is not None else "",
                depth=depth,
            )
            self._tasks[task_id] = task
        return task

    def claim(self, *, role: str = "", claimed_by: str = "") -> Task | None:
        """Atomically claim the oldest pending task matching *role*.

        An empty *role* claims the oldest pending task of any role.  Returns the
        claimed task, or ``None`` when nothing is pending for that role.
        """
        want = role.strip()
        with self._lock:
            pending = [task for task in self._tasks.values() if task.status == TaskStatus.PENDING]
            if want:
                pending = [task for task in pending if task.role == want or task.role == ""]
            if not pending:
                return None
            task = min(pending, key=lambda task: task.ts)
            task.status = TaskStatus.CLAIMED
            task.claimed_by = claimed_by
            return task

    def complete(self, task_id: str, summary: str = "") -> bool:
        return self._finish(task_id, TaskStatus.COMPLETED, summary)

    def fail(self, task_id: str, reason: str = "") -> bool:
        return self._finish(task_id, TaskStatus.FAILED, reason)

    def _finish(self, task_id: str, status: TaskStatus, summary: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                return False
            task.status = status
            task.result_summary = summary
            return True

    def list(self, *, status: TaskStatus | None = None, role: str = "") -> list[Task]:
        want_role = role.strip()
        with self._lock:
            tasks = list(self._tasks.values())
        if status is not None:
            tasks = [task for task in tasks if task.status == status]
        if want_role:
            tasks = [task for task in tasks if task.role == want_role]
        return sorted(tasks, key=lambda task: task.ts)

    def pending_count(self, role: str = "") -> int:
        return len(self.list(status=TaskStatus.PENDING, role=role))

    def has_open_work(self) -> bool:
        """True while any task is still pending or claimed (drives the scheduler)."""
        with self._lock:
            return any(
                task.status in (TaskStatus.PENDING, TaskStatus.CLAIMED) for task in self._tasks.values()
            )
