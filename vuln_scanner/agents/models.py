"""Typed models for the agentic layer — config, findings, PoCs, and reports.

Import-light on purpose (only pydantic + tool enums): this module is referenced
from the config layer, so it must not pull in openai / pydantic-ai.
"""

from enum import Enum

from pydantic import BaseModel, Field

from vuln_scanner.tools.enums import Severity


class AgentKind(str, Enum):
    """The two supported agent profiles."""

    BUG_BOUNTY = "bug_bounty"  # non-destructive; prove a bug exists
    PENTESTER = "pentester"  # exploitation for PoC only; dry-run by default


class AgentStatus(str, Enum):
    """Terminal status of an agent run."""

    COMPLETED = "completed"  # agent finished on its own
    TIMED_OUT = "timed_out"  # wall-clock deadline hit → summarized
    CEILING = "ceiling"  # tool-call / token ceiling hit → summarized
    ERROR = "error"  # crashed; partial results only
    SKIPPED = "skipped"  # not run (disabled / not in container)


# ── Sandbox / execution limits ───────────────────────────────────────────────


class SandboxConfig(BaseModel):
    """Resource limits applied to agent code execution (``run_code``).

    These map to POSIX rlimits and container network policy.  They bound
    arbitrary code the agent writes so a runaway / fork bomb / disk filler
    cannot take down the host even if the denylist misses it.
    """

    cpu_seconds: int = 30  # RLIMIT_CPU
    memory_mb: int = 512  # RLIMIT_AS
    max_procs: int = 64  # RLIMIT_NPROC (fork-bomb guard)
    file_size_mb: int = 50  # RLIMIT_FSIZE
    timeout: int = 120  # wall-clock kill for a single exec
    # Network policy for run_code: "lab" = scope-restricted (default),
    # "none" = no network at all, "host" = unrestricted (NOT recommended).
    network: str = "lab"


# ── Bug-submission-shaped finding ────────────────────────────────────────────


class AgentFinding(BaseModel):
    """A bug an agent discovered — shaped for a bug-bounty submission.

    Richer than a scanner ``Finding``: carries reproduction steps, request/
    response evidence, impact, and OOB proof so a report can be submitted as-is.
    """

    title: str
    severity: Severity = Severity.INFO
    target: str = ""
    affected_url: str = ""
    affected_param: str = ""
    vuln_class: list[str] = Field(default_factory=list)  # CWE ids / class names
    summary: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    request: str = ""  # raw HTTP request evidence
    response: str = ""  # raw HTTP response evidence
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    oob_evidence: str = ""  # interactsh / OAST interaction proof
    cvss_vector: str = ""
    cvss_score: float | None = None
    confidence: str = "unknown"
    # True once an independent verification re-run reproduced the bug (M7).
    verified: bool = False
    discovered_by: str = ""  # agent name


class AgentPoc(BaseModel):
    """A proof-of-concept artifact produced by an agent."""

    id: str
    finding_title: str = ""
    language: str = ""
    description: str = ""
    command: str = ""  # exact command / invocation
    script_path: str = ""  # written artifact, if any
    expected_indicator: str = ""
    executed: bool = False  # whether it was actually run (vs. dry-run plan)
    verdict: str = "not_run"  # confirmed / inconclusive / failed / not_run
    evidence: str = ""  # captured output proving the PoC


class AgentReport(BaseModel):
    """The typed result of a single agent run — the agent's structured output."""

    agent_name: str
    kind: AgentKind
    status: AgentStatus = AgentStatus.COMPLETED
    summary: str = ""
    findings: list[AgentFinding] = Field(default_factory=list)
    pocs: list[AgentPoc] = Field(default_factory=list)
    # Pentester dry-run: ordered exploit plan (commands + rationale) that was
    # NOT executed because live exploitation was gated off.
    exploit_plan: list[str] = Field(default_factory=list)
    actions_taken: int = 0
    tokens_used: int | None = None
    duration: float = 0.0
    action_log_path: str = ""  # run_dir/agent_logs/<agent>.jsonl


# ── Configuration ────────────────────────────────────────────────────────────


class AgentConfig(BaseModel):
    """Per-agent configuration.  Connection/sampling fall back to LLMConfig."""

    name: str
    kind: AgentKind
    enabled: bool = True

    # Prompt override — empty falls back to the kind's built-in default.
    system_prompt: str = ""

    # Model/sampling overrides (empty/None → inherit from LLMConfig).
    model: str = ""
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None  # per-request cap (sampling)

    # Ceilings / lifecycle.
    timeout: int = 600  # wall-clock seconds for the whole agent run
    max_tool_calls: int = 40  # hard stop → summarize
    token_budget: int | None = 500_000  # total-token ceiling → summarize (None = unbounded)

    # Tool access filters (names of agent tools, e.g. "run_tool", "run_code").
    allowed_tools: list[str] = Field(default_factory=list)  # empty = all
    denied_tools: list[str] = Field(default_factory=list)

    # Pentester exploitation gating.
    allow_exploitation: bool = False  # live exec (needs container + active mode)
    require_approval: bool = False  # write plan and stop even if allowed


class SubmissionConfig(BaseModel):
    """Bug-bounty submission report rendering."""

    enabled: bool = True
    # Overridable template (empty → built-in default).  Uses str.format fields.
    template: str = ""
    # Report formats for submissions (falls back to report.formats if empty).
    formats: list[str] = Field(default_factory=list)


class AgentsConfig(BaseModel):
    """Top-level configuration for the agentic layer."""

    enabled: bool = False  # master switch (also requires VS_IN_CONTAINER)
    # Hard scope guard on every host an agent touches.  Cannot be silently
    # disabled inside the container without this explicit flag.
    scope_enforcement: bool = True
    agents: list[AgentConfig] = Field(default_factory=list)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    submission: SubmissionConfig = Field(default_factory=SubmissionConfig)

    def active_agents(self) -> list[AgentConfig]:
        return [a for a in self.agents if a.enabled]
