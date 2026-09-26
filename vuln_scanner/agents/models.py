"""Typed models for the agentic layer — config, findings, PoCs, and reports.

Import-light on purpose (pydantic, tool enums, sibling model modules, and the
stdlib only): this module is referenced from the config layer, so it must not
pull in openai / pydantic-ai.  Model definitions live here so the runtime
modules can stay free of data-shape declarations.
"""

from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from vuln_scanner.agents.scrub import scrub_text
from vuln_scanner.tools.enums import Confidence, Severity
from vuln_scanner.tools.models import Finding


class AgentKind(str, Enum):
    """The two supported agent profiles.

    ``BUG_BOUNTY`` is non-destructive and only proves a bug exists;
    ``PENTESTER`` produces proof-of-concept exploitation and is dry-run by
    default.
    """

    BUG_BOUNTY = "bug_bounty"
    PENTESTER = "pentester"


class AgentStatus(str, Enum):
    """Terminal status of an agent run.

    ``COMPLETED`` — finished on its own; ``TIMED_OUT`` — wall-clock deadline hit
    and summarized; ``CEILING`` — tool-call / token ceiling hit and summarized;
    ``ERROR`` — crashed, partial results only; ``SKIPPED`` — not run (disabled or
    not in the container).
    """

    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    CEILING = "ceiling"
    ERROR = "error"
    SKIPPED = "skipped"


class NetworkPolicy(str, Enum):
    """Network policy applied to sandboxed ``run_code`` execution.

    ``LAB`` — scope-restricted egress (default); ``NONE`` — no network at all;
    ``HOST`` — unrestricted host network (not recommended).
    """

    LAB = "lab"
    NONE = "none"
    HOST = "host"


_LANGUAGE_EXTENSIONS: dict[str, str] = {
    "python": ".py",
    "bash": ".sh",
    "sh": ".sh",
    "ruby": ".rb",
    "perl": ".pl",
    "php": ".php",
    "javascript": ".js",
    "node": ".js",
}

_UNKNOWN_LANGUAGE_EXTENSION = ".txt"


class CodeLanguage(str, Enum):
    """Languages the sandbox can execute, with their source-file extensions."""

    PYTHON = "python"
    BASH = "bash"
    SH = "sh"
    RUBY = "ruby"
    PERL = "perl"
    PHP = "php"
    JAVASCRIPT = "javascript"
    NODE = "node"

    @classmethod
    def from_name(cls, name: str) -> "CodeLanguage | None":
        """Resolve a case-insensitive language name, or ``None`` if unsupported."""
        try:
            return cls(name.lower().strip())
        except ValueError:
            return None

    @property
    def extension(self) -> str:
        return _LANGUAGE_EXTENSIONS[self.value]

    @staticmethod
    def extension_for(name: str) -> str:
        """Source-file extension for *name*, or a neutral default when unknown."""
        language = CodeLanguage.from_name(name)
        return language.extension if language else _UNKNOWN_LANGUAGE_EXTENSION


# ── Sandbox / execution limits ───────────────────────────────────────────────


class SandboxConfig(BaseModel):
    """Resource limits applied to agent code execution (``run_code``).

    These map to POSIX rlimits and container network policy.  They bound
    arbitrary code the agent writes so a runaway / fork bomb / disk filler
    cannot take down the host even if the denylist misses it.
    """

    cpu_seconds: int = Field(30, description="RLIMIT_CPU ceiling in seconds for a single execution.")
    memory_mb: int = Field(512, description="RLIMIT_AS address-space ceiling in megabytes.")
    max_procs: int = Field(64, description="RLIMIT_NPROC process ceiling — the fork-bomb guard.")
    file_size_mb: int = Field(50, description="RLIMIT_FSIZE ceiling in megabytes for created files.")
    timeout: int = Field(120, description="Wall-clock kill timeout in seconds for a single execution.")
    network: NetworkPolicy = Field(NetworkPolicy.LAB, description="Network policy applied to run_code execution.")


class SandboxResult(BaseModel):
    """Outcome of one sandboxed execution (or the reason it was refused)."""

    language: str = Field(description="Normalized language the code was run as.")
    exit_code: int | None = Field(None, description="Process exit code, or None when not run.")
    stdout: str = Field("", description="Captured standard output (truncated).")
    stderr: str = Field("", description="Captured standard error (truncated).")
    timed_out: bool = Field(False, description="True when the wall-clock timeout killed the process.")
    duration: float = Field(0.0, description="Execution wall-clock time in seconds.")
    blocked: bool = Field(False, description="True when execution was refused before it started.")
    block_reason: str = Field("", description="Why execution was refused, when blocked.")
    network: str = Field("", description="Network policy that was in effect.")


# ── Bug-submission-shaped finding ────────────────────────────────────────────


class AgentFinding(BaseModel):
    """A bug an agent discovered — the report/submission-shaped finding.

    Richer than a scanner ``Finding``: carries reproduction steps, request/
    response evidence, impact, and OOB proof so a report can be submitted as-is.
    :meth:`to_finding` folds it back into the scanner findings pipeline and
    :meth:`scrub_secrets` redacts its free-text fields in place.
    """

    title: str = Field(description="Human-readable vulnerability title.")
    severity: Severity = Field(Severity.INFO, description="Assessed severity.")
    target: str = Field("", description="Primary in-scope target the bug affects.")
    affected_url: str = Field("", description="Specific affected URL, if any.")
    affected_param: str = Field("", description="Affected request parameter, if any.")
    vuln_class: list[str] = Field(default_factory=list, description="CWE ids / vulnerability class names.")
    summary: str = Field("", description="Concise description of the bug.")
    reproduction_steps: list[str] = Field(default_factory=list, description="Ordered steps to reproduce.")
    request: str = Field("", description="Raw HTTP request evidence.")
    response: str = Field("", description="Raw HTTP response evidence.")
    impact: str = Field("", description="Security impact of the bug.")
    remediation: str = Field("", description="Suggested remediation.")
    references: list[str] = Field(default_factory=list, description="Supporting reference URLs.")
    oob_evidence: str = Field("", description="Out-of-band (OAST) interaction proof.")
    cvss_vector: str = Field("", description="CVSS vector string.")
    cvss_score: float | None = Field(None, description="CVSS base score.")
    confidence: str = Field("unknown", description="Reporter confidence in the finding.")
    verified: bool = Field(False, description="True once an independent re-run reproduced the bug.")
    discovered_by: str = Field("", description="Name of the agent that discovered the bug.")

    def to_finding(self, agent_name: str) -> Finding:
        """Convert to a scanner ``Finding`` tagged with the discovering agent."""
        return Finding(
            title=self.title,
            severity=self.severity,
            description=self.summary or self.impact or self.title,
            tool=f"agent:{self.discovered_by or agent_name}",
            target=self.target or self.affected_url or "agent",
            cve=[],
            references=list(self.references),
            cwe=list(self.vuln_class),
            request=self.request,
            response=self.response,
            remediation=self.remediation,
            confidence=_to_confidence(self.confidence),
            exploitability=self.impact,
            cvss_vector=self.cvss_vector,
            cvss_score=self.cvss_score,
            raw={"agent": agent_name, "verified": self.verified, "oob_evidence": self.oob_evidence},
        )

    def scrub_secrets(self) -> None:
        """Redact secret-shaped substrings in every free-text field, in place."""
        self.summary = scrub_text(self.summary)
        self.request = scrub_text(self.request)
        self.response = scrub_text(self.response)
        self.oob_evidence = scrub_text(self.oob_evidence)
        self.impact = scrub_text(self.impact)
        self.reproduction_steps = [scrub_text(step) for step in self.reproduction_steps]


def _to_confidence(value: str) -> Confidence:
    """Map a free-text confidence label onto the ``Confidence`` enum."""
    try:
        return Confidence(value.lower())
    except (ValueError, AttributeError):
        return Confidence.UNKNOWN


class AgentPoc(BaseModel):
    """A proof-of-concept artifact produced by an agent."""

    id: str = Field("", description="Stable PoC identifier, e.g. agent-poc-001.")
    finding_title: str = Field("", description="Title of the finding this PoC proves.")
    language: str = Field("", description="Language the PoC is written in.")
    description: str = Field("", description="What the PoC demonstrates.")
    command: str = Field("", description="Exact command / invocation.")
    script_path: str = Field("", description="Path to the written PoC script, if any.")
    expected_indicator: str = Field("", description="Marker that proves the PoC succeeded.")
    executed: bool = Field(False, description="Whether the PoC was actually run (vs. a dry-run plan).")
    verdict: str = Field("not_run", description="confirmed / inconclusive / failed / not_run.")
    evidence: str = Field("", description="Captured output proving the PoC.")

    def scrub_secrets(self) -> None:
        """Redact secret-shaped substrings in the PoC's free-text fields."""
        self.evidence = scrub_text(self.evidence)
        self.command = scrub_text(self.command)


class AgentNote(BaseModel):
    """One timestamped working-memory note in an agent's scratchpad."""

    seq: int = Field(description="1-based sequence number in the scratchpad.")
    tag: str = Field("", description="Optional grouping tag for the note.")
    text: str = Field(description="Note body (truncated to the audit field width).")
    ts: float = Field(default_factory=time.time, description="Unix timestamp when the note was recorded.")


class AgentReport(BaseModel):
    """The typed result of a single agent run — the agent's structured output."""

    agent_name: str = Field(description="Name of the agent that produced this report.")
    kind: AgentKind = Field(description="Agent profile that produced this report.")
    status: AgentStatus = Field(AgentStatus.COMPLETED, description="Terminal status of the run.")
    summary: str = Field("", description="Free-text summary of what the agent did and found.")
    findings: list[AgentFinding] = Field(default_factory=list, description="Bugs the agent saved.")
    pocs: list[AgentPoc] = Field(default_factory=list, description="Proof-of-concept artifacts.")
    exploit_plan: list[str] = Field(
        default_factory=list,
        description="Ordered dry-run exploit steps recorded but NOT executed.",
    )
    actions_taken: int = Field(0, description="Number of tool calls the agent made.")
    tokens_used: int | None = Field(None, description="Total tokens consumed, when known.")
    duration: float = Field(0.0, description="Run wall-clock time in seconds.")
    action_log_path: str = Field("", description="Path to the run's JSONL audit log.")

    def scrub_secrets(self) -> None:
        """Redact secret-shaped substrings across the whole report, in place."""
        self.summary = scrub_text(self.summary)
        self.exploit_plan = [scrub_text(step) for step in self.exploit_plan]
        for finding in self.findings:
            finding.scrub_secrets()
        for poc in self.pocs:
            poc.scrub_secrets()


# ── Audit ────────────────────────────────────────────────────────────────────


class ActionRecord(BaseModel):
    """One append-only audit record for a guarded agent action.

    Action-specific fields (tool name, target, stdout, …) are accepted as extra
    keys so a single model shapes every record without a property explosion.
    """

    model_config = ConfigDict(extra="allow")

    ts: float = Field(default_factory=time.time, description="Unix timestamp of the action.")
    agent: str = Field(description="Name of the agent that took the action.")
    action: str = Field(description="Action verb, e.g. run_tool / scope_deny.")


# ── Configuration ────────────────────────────────────────────────────────────


class AgentConfig(BaseModel):
    """Per-agent configuration.  Connection/sampling fall back to ``LLMConfig``."""

    name: str = Field(description="Unique agent name.")
    kind: AgentKind = Field(description="Agent profile to run.")
    enabled: bool = Field(True, description="Whether the agent participates in a run.")
    system_prompt: str = Field(
        "", description="Prompt override; empty falls back to the kind's built-in default."
    )
    model: str = Field("", description="Model override; empty inherits from LLMConfig.")
    temperature: float | None = Field(None, description="Sampling temperature override.")
    top_p: float | None = Field(None, description="Nucleus-sampling override.")
    max_tokens: int | None = Field(None, description="Per-request sampling token cap.")
    timeout: int = Field(600, description="Wall-clock seconds for the whole agent run.")
    max_tool_calls: int = Field(40, description="Hard tool-call ceiling that triggers a summary.")
    token_budget: int | None = Field(
        500_000, description="Total-token ceiling that triggers a summary (None = unbounded)."
    )
    allowed_tools: list[str] = Field(default_factory=list, description="Permitted tool names (empty = all).")
    denied_tools: list[str] = Field(default_factory=list, description="Explicitly denied tool names.")
    allow_exploitation: bool = Field(
        False, description="Permit live exploitation (needs container + active mode)."
    )
    require_approval: bool = Field(False, description="Write the exploit plan and stop even if allowed.")


class SubmissionConfig(BaseModel):
    """Bug-bounty submission report rendering."""

    enabled: bool = Field(True, description="Whether submission files are written.")
    template: str = Field("", description="Overridable str.format template (empty = built-in default).")
    formats: list[str] = Field(
        default_factory=list, description="Submission formats; falls back to report.formats when empty."
    )


class OrchestrationConfig(BaseModel):
    """Multi-agent orchestration: a lead delegates to concurrent specialists.

    When ``enabled``, the agent phase ignores the flat ``agents`` list and runs
    a lead-plus-specialists team scheduled by the supervisor instead of the
    sequential single-agent loop.  The caps bound the blast radius and cost of
    the team the same way per-agent ceilings bound one agent.
    """

    enabled: bool = Field(False, description="Run the lead-plus-specialists team instead of the flat list.")
    max_concurrent: int = Field(
        3, description="Max specialists running at once; never two on the same host."
    )
    max_rounds: int = Field(3, description="Plan→execute rounds; each round the lead may post follow-ups.")
    max_agent_runs: int = Field(20, description="Hard ceiling on total specialist runs across all rounds.")
    max_tasks: int = Field(100, description="Task-queue cap on total tasks posted (see tasks.TaskQueue).")
    max_depth: int = Field(3, description="Task-queue cap on delegation depth (see tasks.TaskQueue).")
    agent_timeout: int = Field(600, description="Per-role-agent wall-clock timeout in seconds.")
    max_tool_calls: int = Field(40, description="Per-role-agent tool-call ceiling.")
    token_budget: int | None = Field(500_000, description="Per-role-agent total-token ceiling (None = unbounded).")
    lead_role: str = Field("lead", description="Role name of the coordinating lead agent.")
    specialists: list[str] = Field(
        default_factory=list, description="Specialist role names to run; empty means all built-in specialists."
    )


class AgentsConfig(BaseModel):
    """Top-level configuration for the agentic layer."""

    enabled: bool = Field(False, description="Master switch (also requires VS_IN_CONTAINER).")
    scope_enforcement: bool = Field(
        True, description="Hard scope guard on every host an agent touches; cannot be silently disabled."
    )
    agents: list[AgentConfig] = Field(default_factory=list, description="Configured agents.")
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig, description="Sandbox resource limits.")
    submission: SubmissionConfig = Field(
        default_factory=SubmissionConfig, description="Submission rendering config."
    )
    orchestration: OrchestrationConfig = Field(
        default_factory=OrchestrationConfig, description="Multi-agent orchestration config."
    )

    def active_agents(self) -> list[AgentConfig]:
        return [agent for agent in self.agents if agent.enabled]
