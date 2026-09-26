"""AgentDeps — the RunContext dependency object shared by all agent tools.

Carries the scope guard, sandbox/config, audit log, artifact dir, wall-clock
deadline, and the mutable collectors an agent fills in.  Every host-touching
agent tool must call :meth:`AgentDeps.assert_in_scope` before acting.
"""

import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.blackboard import EngagementState
from vuln_scanner.agents.guards import canonical_host, extract_hosts, is_in_container
from vuln_scanner.agents.models import AgentConfig, AgentFinding, AgentNote, AgentPoc, AgentsConfig
from vuln_scanner.agents.oob import OobSession
from vuln_scanner.agents.tasks import Task, TaskQueue
from vuln_scanner.scope import ScopeValidator


class ScopeViolation(Exception):
    """Raised when an agent action targets an out-of-scope host."""


class ContainerGateError(Exception):
    """Raised when a container-only action is attempted outside the container."""


def _default_code_languages() -> list[str]:
    return ["python", "bash"]


class AgentDeps(BaseModel):
    """Dependencies + mutable state for a single agent run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent: AgentConfig = Field(description="Configuration of the agent this context serves.")
    agents_cfg: AgentsConfig = Field(description="Top-level agentic-layer configuration.")
    scope: ScopeValidator = Field(description="Validator for the assessment scope.")
    audit: ActionLog = Field(description="Append-only audit log for this agent's actions.")
    artifact_dir: Path = Field(description="Directory for PoC scripts and other artifacts.")
    allowlist: set[str] = Field(
        default_factory=set,
        description="Original scan targets + in-scope discovered assets allowed without a scope check.",
    )
    deadline: float | None = Field(
        None, description="Monotonic wall-clock deadline in seconds; None means no deadline."
    )
    live_exploit_allowed: bool = Field(
        False, description="Whether live exploitation may actually execute (pentester gate)."
    )
    tool_calls: int = Field(0, description="Running count of tool calls, for the ceiling.")
    code_languages: list[str] = Field(
        default_factory=_default_code_languages, description="Languages the sandbox accepts for run_code."
    )
    oob_server: str = Field("", description="interactsh/OAST server URL, if configured.")
    oob_token: str = Field("", description="interactsh/OAST auth token, if configured.")
    oob_session: OobSession | None = Field(None, description="Lazily-started OOB session.")
    findings: list[AgentFinding] = Field(default_factory=list, description="Bugs the agent has saved.")
    pocs: list[AgentPoc] = Field(default_factory=list, description="PoC artifacts the agent has recorded.")
    exploit_plan: list[str] = Field(
        default_factory=list, description="Dry-run exploit-plan steps recorded but not executed."
    )
    notes: list[AgentNote] = Field(
        default_factory=list,
        description="Working-memory scratchpad notes; never surfaced into the report by default.",
    )

    # Multi-agent collaboration — all default to the safe, non-collaborative
    # value so a solo agent behaves exactly as before.
    blackboard: EngagementState | None = Field(
        None, description="Shared engagement blackboard, or None on the single-agent path."
    )
    task_queue: TaskQueue | None = Field(
        None, description="Shared delegation task queue, or None on the single-agent path."
    )
    role: str = Field("", description="This agent's specialist role name.")
    current_task: Task | None = Field(None, description="The task this agent is currently handling.")
    can_delegate: bool = Field(
        False, description="Enforced privilege boundary: only a delegating role may post tasks."
    )

    # ── Gates ────────────────────────────────────────────────────────────────

    def require_container(self, action: str) -> None:
        """Refuse a container-only action outside the Docker image."""
        if not is_in_container():
            self.audit.record(action, refused="not_in_container")
            raise ContainerGateError(f"{action} is only allowed inside the container (VS_IN_CONTAINER=1).")

    def past_deadline(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def assert_in_scope(self, *values: str) -> None:
        """Validate every host referenced in *values* against scope.

        Extracts hosts from URLs / host:port / bare domains / IPs and rejects the
        action if any is out of scope.  A value with no extractable host is
        allowed (nothing to reach); the sandbox network policy is the backstop.
        """
        if not self.agents_cfg.scope_enforcement:
            self.audit.record("scope_check", enforcement="disabled", values=list(values))
            return

        for host in extract_hosts(*values):
            self._reject_if_out_of_scope(host, values=list(values))

    def assert_target_in_scope(self, target: str) -> None:
        """Fail-closed scope check for an *explicit* single target field.

        Where :meth:`assert_in_scope` scans free text and allows values with no
        extractable host (a bare path, pure code), this is for a field the
        caller declares to be a host / URL to act on: ``record_credential(host=)``,
        ``record_asset`` of a host-like type, ``post_task(target=)``.  A
        non-empty target that resolves to no in-scope host is REJECTED, so a
        single-label host (``localhost``), an IPv6 literal, or a homoglyph
        domain cannot slip through the way it would on the best-effort path.
        """
        if not self.agents_cfg.scope_enforcement:
            self.audit.record("scope_check", enforcement="disabled", target=target)
            return
        target = (target or "").strip()
        if not target:
            return

        hosts = extract_hosts(target)
        if not hosts:
            candidate = canonical_host(target)
            if candidate:
                hosts = {candidate}
        if not hosts:
            self.audit.record("scope_deny", reason="unparseable_target", target=target)
            raise ScopeViolation(f"Target {target!r} could not be validated against scope and was refused.")
        for host in hosts:
            self._reject_if_out_of_scope(host, target=target)

    def _reject_if_out_of_scope(self, host: str, **audit_fields: object) -> None:
        if host in self.allowlist:
            return
        if not self.scope.is_in_scope(host, discovered=True):
            self.audit.record("scope_deny", host=host, **audit_fields)
            raise ScopeViolation(
                f"Host {host!r} is out of scope. Allowed targets are limited to the "
                f"assessment scope; pick an in-scope target."
            )

    # ── Tool-call ceiling ────────────────────────────────────────────────────

    def bump_tool_call(self) -> None:
        self.tool_calls += 1

    def ceiling_reached(self) -> bool:
        return self.tool_calls >= self.agent.max_tool_calls
