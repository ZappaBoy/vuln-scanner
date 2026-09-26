"""AgentDeps — the RunContext dependency object shared by all agent tools.

Carries the scope guard, sandbox/config, audit log, artifact dir, wall-clock
deadline, and the mutable collectors an agent fills in.  Every host-touching
agent tool must call :meth:`AgentDeps.assert_in_scope` before acting.
"""

import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.guards import extract_hosts, is_in_container
from vuln_scanner.agents.models import AgentConfig, AgentFinding, AgentNote, AgentPoc, AgentsConfig
from vuln_scanner.agents.oob import OobSession
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

        hosts = extract_hosts(*values)
        for host in hosts:
            if host in self.allowlist:
                continue
            if not self.scope.is_in_scope(host, discovered=True):
                self.audit.record("scope_deny", host=host, values=list(values))
                raise ScopeViolation(
                    f"Host {host!r} is out of scope. Allowed targets are limited to the "
                    f"assessment scope; pick an in-scope target."
                )

    # ── Tool-call ceiling ────────────────────────────────────────────────────

    def bump_tool_call(self) -> None:
        self.tool_calls += 1

    def ceiling_reached(self) -> bool:
        return self.tool_calls >= self.agent.max_tool_calls
