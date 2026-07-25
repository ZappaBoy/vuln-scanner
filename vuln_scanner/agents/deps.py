"""AgentDeps — the RunContext dependency object shared by all agent tools.

Carries the scope guard, sandbox/config, audit log, artifact dir, wall-clock
deadline, and the mutable collectors an agent fills in.  Every host-touching
agent tool must call :meth:`AgentDeps.assert_in_scope` before acting.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.guards import extract_hosts, is_in_container
from vuln_scanner.agents.models import AgentConfig, AgentFinding, AgentPoc, AgentsConfig
from vuln_scanner.scope import ScopeValidator

if TYPE_CHECKING:
    from vuln_scanner.agents.oob import OobSession


class ScopeViolation(Exception):
    """Raised when an agent action targets an out-of-scope host."""


class ContainerGateError(Exception):
    """Raised when a container-only action is attempted outside the container."""


@dataclass
class AgentDeps:
    """Dependencies + mutable state for a single agent run."""

    agent: AgentConfig
    agents_cfg: AgentsConfig
    scope: ScopeValidator
    audit: ActionLog
    artifact_dir: Path
    # Explicit allowlist (original scan targets + in-scope discovered assets).
    allowlist: set[str] = field(default_factory=set)
    # Wall-clock deadline (monotonic seconds); None = no deadline.
    deadline: float | None = None
    # Whether live exploitation may actually execute (pentester gate):
    # allow_exploitation AND active/aggressive mode AND container AND not require_approval.
    live_exploit_allowed: bool = False
    # Ceiling on tool calls; incremented by the runner/tools.
    tool_calls: int = 0
    # Languages the sandbox will accept for run_code (from PoC config).
    code_languages: list[str] = field(default_factory=lambda: ["python", "bash"])
    # OOB/interactsh server + token (from nuclei config) and lazy session.
    oob_server: str = ""
    oob_token: str = ""
    oob_session: "OobSession | None" = None
    # Collectors the agent tools append to.
    findings: list[AgentFinding] = field(default_factory=list)
    pocs: list[AgentPoc] = field(default_factory=list)
    exploit_plan: list[str] = field(default_factory=list)

    # ── Gates ────────────────────────────────────────────────────────────────

    def require_container(self, action: str) -> None:
        """Refuse a container-only action outside the Docker image."""
        if not is_in_container():
            self.audit.record(action, refused="not_in_container")
            raise ContainerGateError(
                f"{action} is only allowed inside the container (VS_IN_CONTAINER=1)."
            )

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
