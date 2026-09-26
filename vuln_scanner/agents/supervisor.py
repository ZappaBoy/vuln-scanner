"""Supervisor — schedules a lead-plus-specialists agent team.

The supervisor turns the collaboration primitives (blackboard, task queue,
roles) into a running engagement:

1. Seed a shared :class:`EngagementState` from the assessment and build a
   :class:`TaskQueue`.
2. Run the lead agent, which reads shared state and delegates tasks to
   specialists via ``post_task``.
3. Drain the pending tasks by running specialist agents CONCURRENTLY, bounded
   by ``max_concurrent`` and by a per-host lock so two agents never act on the
   same host at once (the reason the legacy path ran strictly sequentially).
4. Repeat for up to ``max_rounds`` planning rounds so the lead can react to what
   specialists discovered — the iterate/delegate loop — stopping early when a
   round produces no new work.

Every agent still runs under its own ceilings and the same guards; the
supervisor only decides who runs when, never what an agent is allowed to do.
Cost/blast-radius is bounded by ``max_rounds``, ``max_agent_runs``, and the
queue's own ``max_tasks`` / ``max_depth`` caps.
"""

import asyncio
import logging
from typing import TYPE_CHECKING

from vuln_scanner.agents.guards import canonical_host
from vuln_scanner.agents.models import AgentReport, OrchestrationConfig
from vuln_scanner.agents.roles import LEAD_ROLE, get_role, specialist_role_names
from vuln_scanner.agents.tasks import Task, TaskQueue

if TYPE_CHECKING:
    from vuln_scanner.agents.blackboard import EngagementState
    from vuln_scanner.agents.runner import AgentOrchestrator
    from vuln_scanner.model import Assessment

log = logging.getLogger(__name__)

_MAX_SEED_FINDINGS = 40
_MAX_STATE_ASSETS = 25


class Supervisor:
    def __init__(self, orchestrator: "AgentOrchestrator", cfg: OrchestrationConfig) -> None:
        self._orch = orchestrator
        self._cfg = cfg
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._runs = 0  # specialist runs so far (bounded by max_agent_runs)

    async def orchestrate(self, assessment: "Assessment") -> list[AgentReport]:
        blackboard = self._orch.new_blackboard()
        queue = TaskQueue(max_tasks=self._cfg.max_tasks, max_depth=self._cfg.max_depth)
        self._seed_blackboard(blackboard, assessment)

        lead_role = get_role(self._cfg.lead_role) or get_role(LEAD_ROLE)
        reports: list[AgentReport] = []

        for round_num in range(1, self._cfg.max_rounds + 1):
            if self._runs >= self._cfg.max_agent_runs:
                log.info("Supervisor: agent-run budget (%d) reached.", self._cfg.max_agent_runs)
                break

            lead_prompt = self._lead_prompt(assessment, blackboard, round_num)
            log.info("Supervisor: round %d — lead planning.", round_num)
            lead_report = await self._orch.run_role_agent(
                lead_role, lead_prompt, blackboard=blackboard, task_queue=queue, label=f"lead-r{round_num}"
            )
            reports.append(lead_report)

            if queue.pending_count() == 0:
                log.info("Supervisor: round %d — lead posted no tasks; stopping.", round_num)
                break

            round_reports = await self._drain_pending(queue, blackboard)
            reports.extend(round_reports)
            if not round_reports:
                break

        log.info(
            "Supervisor: finished — %d agent run(s), blackboard %s.",
            len(reports),
            blackboard.counts(),
        )
        return reports

    # ── Task draining (concurrent, per-host serialized) ──────────────────────

    async def _drain_pending(self, queue: TaskQueue, blackboard: "EngagementState") -> list[AgentReport]:
        claimed: list[Task] = []
        while self._runs + len(claimed) < self._cfg.max_agent_runs:
            task = queue.claim(claimed_by="supervisor")
            if task is None:
                break
            claimed.append(task)
        if not claimed:
            return []

        semaphore = asyncio.Semaphore(max(1, self._cfg.max_concurrent))
        results = await asyncio.gather(*[self._run_task(task, queue, blackboard, semaphore) for task in claimed])
        return [r for r in results if r is not None]

    async def _run_task(
        self,
        task: Task,
        queue: TaskQueue,
        blackboard: "EngagementState",
        semaphore: asyncio.Semaphore,
    ) -> AgentReport | None:
        role = get_role(task.role)
        if role is None or task.role not in specialist_role_names():
            queue.fail(task.id, f"unknown role '{task.role}'")
            return None

        self._runs += 1
        prompt = self._specialist_prompt(task, blackboard)
        async with semaphore:
            async with self._host_lock(task.target):
                try:
                    report = await self._orch.run_role_agent(
                        role,
                        prompt,
                        blackboard=blackboard,
                        task_queue=queue,
                        current_task=task,
                        label=f"{task.role}-{task.id}",
                    )
                except Exception as exc:  # a crashing specialist must not sink the round
                    log.exception("Specialist '%s' crashed on %s: %s", task.role, task.id, exc)
                    queue.fail(task.id, f"crashed: {exc}")
                    return None
        queue.complete(task.id, report.summary)
        return report

    def _host_lock(self, target: str) -> asyncio.Lock:
        """Lock keyed on a task's declared target host, so two specialists with
        the same target host never run concurrently.

        This serializes on the *declared* ``task.target`` only; an agent whose
        objective leads it to a host its task never named is not serialized
        against that host (scope enforcement at the tool layer still applies).
        A task with no host target gets its own throwaway lock (uncontended), so
        hostless work still runs in parallel up to ``max_concurrent``.
        """
        host = canonical_host(target) if target else ""
        if not host:
            return asyncio.Lock()
        lock = self._host_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._host_locks[host] = lock
        return lock

    # ── Seeding & prompts ────────────────────────────────────────────────────

    def _seed_blackboard(self, blackboard: "EngagementState", assessment: "Assessment") -> None:
        for host in sorted(self._orch._allowlist):
            blackboard.add_asset("host", host, source="scope")
        # Defense in depth: only seed in-scope scan targets, so an out-of-scope
        # target from an imported/foreign finding is never surfaced to a
        # specialist (the tool layer re-validates scope regardless).
        for _tool, finding in assessment.all_findings:
            target = finding.target or ""
            if target and self._orch._scope.is_in_scope(target, discovered=True):
                blackboard.add_asset("target", target, source=f"scan:{finding.tool}")

    def _lead_prompt(self, assessment: "Assessment", blackboard: "EngagementState", round_num: int) -> str:
        lines = [
            f"You are the lead. Planning round {round_num} of {self._cfg.max_rounds}.",
            "Decompose the objective into concrete tasks and delegate each to a "
            "specialist with post_task(role, objective, target). Available roles: "
            f"{', '.join(specialist_role_names())}.",
            "Call read_state first to see what specialists have already found this "
            "engagement, then post only NEW, well-scoped work. Reply with a short "
            "plan summary when done.",
            "",
            f"In-scope hosts: {', '.join(sorted(self._orch._allowlist)) or '(scope config)'}",
            f"Shared state so far: {blackboard.counts()}",
            "",
            "Findings already reported by automated tools:",
        ]
        count = 0
        for _tool, finding in assessment.all_findings:
            if count >= _MAX_SEED_FINDINGS:
                break
            lines.append(f"- [{finding.severity.value}] {finding.title} @ {finding.target} (via {finding.tool})")
            count += 1
        if count == 0:
            lines.append("- (none — start from recon)")
        return "\n".join(lines)

    def _specialist_prompt(self, task: Task, blackboard: "EngagementState") -> str:
        assets = blackboard.assets()[:_MAX_STATE_ASSETS]
        asset_lines = "\n".join(f"- {a.type}: {a.value}" for a in assets) or "- (none yet)"
        target = task.target or "(see objective / shared state)"
        return (
            f"Delegated task {task.id} for role '{task.role}'.\n"
            f"Objective: {task.objective}\n"
            f"Target: {target}\n\n"
            "Call read_state first to avoid repeating other agents' work. Publish "
            "anything reusable with share_finding / record_asset / record_credential, "
            "save confirmed bugs with save_bug, and reply with a concise summary.\n\n"
            f"Known assets:\n{asset_lines}"
        )
