# Multi-agent engagement layer

The agent phase runs after the static scan and LLM-analysis phases, container-only
(`VS_IN_CONTAINER=1`). It has two modes, selected by `[agents.orchestration].enabled`:

- **Sequential** (default): the configured `[[agents.agents]]` run one at a time
  via `AgentOrchestrator._run_all`, each seeded with the assessment findings.
- **Orchestrated**: a lead agent plans and delegates to specialist agents that
  collaborate through a shared blackboard and a task queue, scheduled
  concurrently by the `Supervisor`. The flat `agents` list is ignored.

Both modes share one tool surface and the same hard guards (scope, denylist,
container gate, sandbox rlimits, usage ceilings, audit log, and — for the
`pentester`/`exploit` profile — the dry-run exploitation gate). Orchestration
adds coordination, not privilege.

## Components

| Module | Responsibility |
|--------|----------------|
| `agents/blackboard.py` | `EngagementState`: shared assets / findings / credentials |
| `agents/tasks.py` | `TaskQueue`, `Task`: delegation hand-off channel |
| `agents/roles.py` | `AgentRole` registry: specialization + safety profile |
| `agents/agent_tools.py` | collaboration tools (`read_state`, `share_finding`, `record_asset`, `record_credential`, `post_task`) |
| `agents/supervisor.py` | `Supervisor`: concurrent lead+specialist scheduler |
| `agents/runner.py` | `AgentOrchestrator`: builds/deps/runs agents; branches on mode |

### EngagementState (`blackboard.py`)
Thread-safe, in-process store for one engagement. Authoritative state is in
memory (agents are threads/coroutines in one process); every mutation is also
appended to `<run_dir>/blackboard/events.jsonl` for audit.

- `add_asset(type, value, source)` / `assets(type="")` — deduped by
  `type:value` (case-insensitive).
- `add_finding(AgentFinding)` / `findings()` — deduped by `title|target`.
- `add_credential(Credential)` / `credentials()` — deduped by
  `kind|user|host|secret`.
- `add_*` returns `True` for a novel item, `False` for a duplicate or when a cap
  (`_MAX_ASSETS` / `_MAX_FINDINGS` / `_MAX_CREDENTIALS`) is hit.

### TaskQueue and roles (`tasks.py`, `roles.py`)
`TaskQueue` is the hand-off channel: `post` (create), `claim` (atomic,
role-matched, FIFO by timestamp), `complete`/`fail` (terminal), `list`,
`has_open_work`. Two caps are enforced inside `post` under the lock:

- `max_tasks` — total tasks ever posted (queue-flood / budget guard).
- `max_depth` — delegation recursion depth; a task posted while a task is being
  handled is `parent.depth + 1`.

`AgentRole` binds a specialization to an **enforced** `AgentKind` (safety
profile) and a `can_delegate` flag. Built-ins: `lead` (bug_bounty, delegates),
`recon` / `web` / `network` / `cloud` (bug_bounty), `exploit` (pentester,
dry-run gate). `builtin_roles()` / `get_role()` return deep copies so shared
role state cannot be mutated by callers.

### Collaboration tools (`agent_tools.py`)
Added to every agent, routed through `_precheck` (ceiling / deadline /
allow-deny filter) and the scope guard. They degrade to an informative message
on the sequential path (no blackboard/queue injected), so solo behavior is
unchanged.

| Tool | Effect | Scope handling |
|------|--------|----------------|
| `read_state(section)` | read shared assets/findings/credentials/tasks | none (read-only); **credential secrets are never returned** |
| `share_finding(...)` | publish a finding to the blackboard | — |
| `record_asset(type, value)` | publish a discovered asset | host-like types → `assert_target_in_scope` (fail closed); others → best-effort |
| `record_credential(kind, secret, ...)` | store loot (secret kept private) | host → `assert_target_in_scope`; secret never audited |
| `post_task(role, objective, target)` | delegate to a specialist | gated on `can_delegate`; target → `assert_target_in_scope`; capped by the queue |

### Supervisor (`supervisor.py`)
`orchestrate(assessment)`:

1. Build `EngagementState` (seeded with in-scope hosts and scan-finding targets)
   and a `TaskQueue`.
2. For up to `max_rounds` rounds: run the lead (it reads state and posts tasks),
   then drain pending tasks. Stop early when a round posts no work or produces
   no specialist runs.
3. Drain = claim pending tasks (bounded by remaining `max_agent_runs`) and run
   them with `asyncio.gather` under an `asyncio.Semaphore(max_concurrent)` and a
   **per-host `asyncio.Lock`** so no two agents act on the same host at once.
   A task with no host target gets a fresh uncontended lock (runs in parallel).
4. Return all `AgentReport`s (lead + specialists); each is verified and scrubbed
   by the shared `runner._run_agent` finalization.

## Data flow

```
assessment ─► Supervisor.seed ─► EngagementState (assets)
                                     ▲            │ read_state
        post_task                    │ share_*    ▼
lead ───────────► TaskQueue ─claim─► specialist agents (concurrent, per-host locked)
  ▲                                  │ save_bug
  └──── round N+1 reads state ◄──────┘ → AgentReport.findings ─► bridge → assessment
```

The lead never scans; specialists never delegate. Hand-off is mediated:
a specialist publishes to the blackboard, the lead observes it on the next round
and posts follow-up tasks. `AgentReport.findings` (from `save_bug`) flow into the
main findings pipeline via `agents/bridge.py`, exactly as in sequential mode.

## Configuration

`[agents.orchestration]` (see `config.example.toml`):

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | orchestrated vs. sequential mode |
| `max_concurrent` | `3` | specialists in flight at once |
| `max_rounds` | `3` | lead plan→execute iterations |
| `max_agent_runs` | `20` | hard ceiling on total specialist runs |
| `max_tasks` | `100` | task-queue size cap |
| `max_depth` | `3` | delegation recursion cap |
| `agent_timeout` | `600` | per-role-agent wall-clock seconds |
| `max_tool_calls` | `40` | per-role-agent tool-call ceiling |
| `token_budget` | `500000` | per-role-agent token ceiling |
| `lead_role` | `"lead"` | coordinating role name |
| `specialists` | all | delegatable specialist roles |

## Security assumptions and limitations

- **Scope is re-validated at point of use.** The blackboard stores data, not
  trust; a host on it is not implicitly in scope. Explicit host/target fields go
  through `assert_target_in_scope`, which **fails closed** (a non-empty target
  that resolves to no in-scope host is rejected — this covers IPv6 literals,
  single-label hosts, and homoglyph-dot domains that the best-effort
  `extract_hosts` scan does not surface). Free-text `run_tool`/`run_code`/
  `http_request` keep the best-effort `assert_in_scope`, which allows values
  with no reachable host.
- **Credential secrets stay private.** They are never returned by `read_state`,
  never written to the audit log or the blackboard event log, and are scrubbed
  from reports by `agents/scrub.py` before anything leaves the process.
- **Delegation is bounded and one-directional.** Only `can_delegate` roles (the
  lead) may `post_task`; specialists cannot spawn work. `max_tasks` /
  `max_depth` / `max_agent_runs` / `max_rounds` bound the delegation tree and
  total cost.
- **Concurrency is host-serialized.** `max_concurrent` bounds parallelism and
  the per-host lock prevents two agents from hammering one host — the invariant
  the legacy strictly-sequential loop provided.
- **`max_depth` is currently latent** in the default wiring: the lead runs with
  no `current_task` (its tasks are depth 1) and specialists cannot delegate, so
  depth never exceeds 1. It is enforced ahead of any future change that lets a
  task-handling agent delegate; such a change must re-verify depth threading.
- In-process only: the blackboard and queue are per-run and are not shared
  across processes or persisted for resume.
