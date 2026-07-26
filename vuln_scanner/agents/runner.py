"""AgentOrchestrator — runs configured agents strictly one at a time.

Sequential by design (no parallelism across agents) so multiple agents never
contend on the same host.  Each agent runs under a wall-clock deadline plus
tool-call / token ceilings; whenever a limit is hit the agent is asked for a
final summary so a report is ALWAYS produced.  Container-only.
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vuln_scanner.agents import agent_tools
from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.deps import AgentDeps
from vuln_scanner.agents.guards import extract_hosts, is_in_container
from vuln_scanner.agents.models import (
    AgentConfig,
    AgentReport,
    AgentsConfig,
    AgentStatus,
)
from vuln_scanner.agents.prompts import system_prompt_for
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools.enums import ScanMode

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig
    from vuln_scanner.model import Assessment

log = logging.getLogger(__name__)

_ACTIVE_MODES = {ScanMode.ACTIVE, ScanMode.AGGRESSIVE}
_MAX_SEED_FINDINGS = 40


class AgentOrchestrator:
    def __init__(
        self,
        agents_cfg: AgentsConfig,
        llm_config: "LLMConfig",
        scope: ScopeValidator,
        run_dir: Path,
        mode: ScanMode,
        allowlist_hosts: set[str],
        code_languages: list[str] | None = None,
        oob_server: str = "",
        oob_token: str = "",
        model: Any = None,  # inject a pydantic-ai model (tests); else built from LLMConfig
    ) -> None:
        self._cfg = agents_cfg
        self._llm = llm_config
        self._scope = scope
        self._run_dir = run_dir
        self._mode = mode
        self._allowlist = allowlist_hosts
        self._code_languages = code_languages or ["python", "bash"]
        self._oob_server = oob_server
        self._oob_token = oob_token
        self._model = model

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self, assessment: "Assessment") -> list[AgentReport]:
        """Run all active agents sequentially. Blocking."""
        if not self._cfg.enabled:
            return []
        if not is_in_container():
            log.warning("Agent phase skipped: not inside container (VS_IN_CONTAINER != 1).")
            return []
        active = self._cfg.active_agents()
        if not active:
            log.info("Agent phase: no active agents configured.")
            return []
        if self._model is None:
            if not self._llm.is_active or not self._llm.model:
                log.warning("Agent phase skipped: LLM not active / no model set.")
                return []
            try:
                self._model = self._build_model()
            except Exception:
                log.exception("Agent phase skipped: could not build LLM model.")
                return []

        log.info("Agent phase: running %d agent(s) sequentially.", len(active))
        return asyncio.run(self._run_all(active, assessment))

    async def _run_all(self, active: list[AgentConfig], assessment: "Assessment") -> list[AgentReport]:
        reports: list[AgentReport] = []
        total = len(active)
        for i, agent_cfg in enumerate(active, 1):  # strictly sequential
            log.info(
                "▶ Agent %d/%d: %s [%s] (timeout %ds, max %d tool calls)…",
                i,
                total,
                agent_cfg.name,
                agent_cfg.kind.value,
                agent_cfg.timeout,
                agent_cfg.max_tool_calls,
            )
            try:
                report = await self._run_one(agent_cfg, assessment)
                log.info(
                    "✓ Agent %d/%d: %s — %s (%d bug(s), %d PoC(s), %d action(s))",
                    i,
                    total,
                    agent_cfg.name,
                    report.status.value,
                    len(report.findings),
                    len(report.pocs),
                    report.actions_taken,
                )
                if self._llm.log_responses and report.summary:
                    flat = " ".join(report.summary.split())
                    log.info("  ↳ %s: %s", agent_cfg.name, flat if len(flat) <= 200 else flat[:199] + "…")
                reports.append(report)
            except Exception as exc:
                log.exception("Agent '%s' crashed: %s", agent_cfg.name, exc)
                reports.append(
                    AgentReport(
                        agent_name=agent_cfg.name,
                        kind=agent_cfg.kind,
                        status=AgentStatus.ERROR,
                        summary=f"Agent crashed: {exc}",
                    )
                )
        return reports

    # ── Single agent ─────────────────────────────────────────────────────────

    async def _run_one(self, agent_cfg: AgentConfig, assessment: "Assessment") -> AgentReport:
        deps = self._build_deps(agent_cfg)
        start = time.monotonic()
        status = AgentStatus.COMPLETED
        summary = ""
        tokens: int | None = None

        agent = self._build_agent(agent_cfg)
        prompt = self._seed_prompt(agent_cfg, assessment)
        usage_limits = self._usage_limits(agent_cfg)

        try:
            result = await asyncio.wait_for(
                agent.run(prompt, deps=deps, usage_limits=usage_limits),
                timeout=agent_cfg.timeout,
            )
            summary = result.output or ""
            tokens = getattr(result.usage, "total_tokens", None)
        except asyncio.TimeoutError:
            log.info("Agent '%s' hit wall-clock timeout — summarizing.", agent_cfg.name)
            status = AgentStatus.TIMED_OUT
            summary = await self._summarize(agent_cfg, deps)
        except Exception as exc:  # includes UsageLimitExceeded
            if type(exc).__name__ == "UsageLimitExceeded":
                log.info("Agent '%s' hit usage ceiling — summarizing.", agent_cfg.name)
                status = AgentStatus.CEILING
                summary = await self._summarize(agent_cfg, deps)
            else:
                raise

        if deps.oob_session is not None:
            deps.oob_session.stop()

        report = AgentReport(
            agent_name=agent_cfg.name,
            kind=agent_cfg.kind,
            status=status,
            summary=summary,
            findings=list(deps.findings),
            pocs=list(deps.pocs),
            exploit_plan=list(deps.exploit_plan),
            actions_taken=deps.tool_calls,
            tokens_used=tokens,
            duration=time.monotonic() - start,
            action_log_path=str(deps.audit.path),
        )

        # Independent verification re-run, then scrub secrets before the report
        # leaves the agent (so submissions and reports are both clean).
        from vuln_scanner.agents.scrub import scrub_report
        from vuln_scanner.agents.verifier import verify_report

        try:
            verify_report(report, sandbox=self._cfg.sandbox, code_languages=self._code_languages)
        except Exception:
            log.exception("Verification pass failed for agent '%s'.", agent_cfg.name)
        return scrub_report(report)

    # ── Construction helpers ─────────────────────────────────────────────────

    def _build_deps(self, agent_cfg: AgentConfig) -> AgentDeps:
        log_dir = self._run_dir / "agent_logs"
        artifact_dir = self._run_dir / "agent_artifacts" / agent_cfg.name
        live = (
            agent_cfg.allow_exploitation
            and self._mode in _ACTIVE_MODES
            and is_in_container()
            and not agent_cfg.require_approval
        )
        return AgentDeps(
            agent=agent_cfg,
            agents_cfg=self._cfg,
            scope=self._scope,
            audit=ActionLog(log_dir, agent_cfg.name),
            artifact_dir=artifact_dir,
            allowlist=set(self._allowlist),
            deadline=time.monotonic() + agent_cfg.timeout,
            live_exploit_allowed=live,
            code_languages=self._code_languages,
            oob_server=self._oob_server,
            oob_token=self._oob_token,
        )

    def _build_agent(self, agent_cfg: AgentConfig):
        from pydantic_ai import Agent, RunContext, Tool

        # Wrap the plain impls so pydantic-ai passes RunContext[AgentDeps].
        def _list_tools(ctx: RunContext[AgentDeps], category: str = "") -> str:
            return agent_tools.list_tools(ctx.deps, category)

        def _run_tool(ctx: RunContext[AgentDeps], tool_name: str, args: list[str], target: str = "") -> dict:
            return agent_tools.run_tool(ctx.deps, tool_name, args, target)

        def _run_code(ctx: RunContext[AgentDeps], language: str, code: str) -> dict:
            return agent_tools.run_code(ctx.deps, language, code)

        def _save_bug(
            ctx: RunContext[AgentDeps],
            title: str,
            severity: str = "info",
            target: str = "",
            affected_url: str = "",
            affected_param: str = "",
            vuln_class: list[str] | None = None,
            summary: str = "",
            reproduction_steps: list[str] | None = None,
            request: str = "",
            response: str = "",
            impact: str = "",
            remediation: str = "",
            references: list[str] | None = None,
            oob_evidence: str = "",
            cvss_vector: str = "",
            cvss_score: float | None = None,
            confidence: str = "unknown",
        ) -> str:
            return agent_tools.save_bug(
                ctx.deps,
                title=title,
                severity=severity,
                target=target,
                affected_url=affected_url,
                affected_param=affected_param,
                vuln_class=vuln_class,
                summary=summary,
                reproduction_steps=reproduction_steps,
                request=request,
                response=response,
                impact=impact,
                remediation=remediation,
                references=references,
                oob_evidence=oob_evidence,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                confidence=confidence,
            )

        def _record_poc(
            ctx: RunContext[AgentDeps],
            finding_title: str,
            language: str,
            description: str,
            command: str = "",
            script: str = "",
            expected_indicator: str = "",
            executed: bool = False,
            verdict: str = "not_run",
            evidence: str = "",
        ) -> str:
            return agent_tools.record_poc(
                ctx.deps,
                finding_title=finding_title,
                language=language,
                description=description,
                command=command,
                script=script,
                expected_indicator=expected_indicator,
                executed=executed,
                verdict=verdict,
                evidence=evidence,
            )

        def _oob_get_callback(ctx: RunContext[AgentDeps]) -> str:
            return agent_tools.oob_get_callback(ctx.deps)

        def _oob_check(ctx: RunContext[AgentDeps]) -> dict:
            return agent_tools.oob_check(ctx.deps)

        tools = [
            Tool(_list_tools, takes_ctx=True, name="list_tools"),
            Tool(_run_tool, takes_ctx=True, name="run_tool"),
            Tool(_run_code, takes_ctx=True, name="run_code"),
            Tool(_save_bug, takes_ctx=True, name="save_bug"),
            Tool(_record_poc, takes_ctx=True, name="record_poc"),
            Tool(_oob_get_callback, takes_ctx=True, name="oob_get_callback"),
            Tool(_oob_check, takes_ctx=True, name="oob_check"),
        ]

        system = agent_cfg.system_prompt or system_prompt_for(agent_cfg.kind)
        return Agent(
            self._model,
            deps_type=AgentDeps,
            output_type=str,
            system_prompt=system,
            tools=tools,
            model_settings=self._model_settings(agent_cfg),
            name=agent_cfg.name,
        )

    def _model_settings(self, agent_cfg: AgentConfig) -> dict | None:
        kw: dict[str, Any] = {}
        temp = agent_cfg.temperature if agent_cfg.temperature is not None else self._llm.temperature
        top_p = agent_cfg.top_p if agent_cfg.top_p is not None else self._llm.top_p
        max_tokens = agent_cfg.max_tokens if agent_cfg.max_tokens is not None else self._llm.max_tokens
        if temp is not None:
            kw["temperature"] = temp
        if top_p is not None:
            kw["top_p"] = top_p
        if max_tokens is not None:
            kw["max_tokens"] = max_tokens
        return kw or None

    def _usage_limits(self, agent_cfg: AgentConfig):
        from pydantic_ai.usage import UsageLimits

        return UsageLimits(
            tool_calls_limit=agent_cfg.max_tool_calls,
            total_tokens_limit=agent_cfg.token_budget,
        )

    def _build_model(self):
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        provider_kwargs: dict[str, Any] = {"api_key": self._llm.api_key or "sk-placeholder"}
        if self._llm.base_url:
            provider_kwargs["base_url"] = self._llm.base_url
        provider = OpenAIProvider(**provider_kwargs)
        return OpenAIChatModel(self._llm.model, provider=provider)

    # ── Prompts ──────────────────────────────────────────────────────────────

    def _seed_prompt(self, agent_cfg: AgentConfig, assessment: "Assessment") -> str:
        lines = [
            "Assess the targets below using your tools. Save every confirmed bug "
            "with evidence, then reply with a concise summary of what you found "
            "and did.",
            "",
            f"In-scope hosts: {', '.join(sorted(self._allowlist)) or '(scope config)'}",
            "",
            "Findings already reported by automated tools:",
        ]
        count = 0
        for _tool, f in assessment.all_findings:
            if count >= _MAX_SEED_FINDINGS:
                break
            lines.append(f"- [{f.severity.value}] {f.title} @ {f.target} (via {f.tool})")
            count += 1
        if count == 0:
            lines.append("- (none — start from recon)")
        return "\n".join(lines)

    async def _summarize(self, agent_cfg: AgentConfig, deps: AgentDeps) -> str:
        """Tool-less final summary call. Falls back to a synthetic summary."""
        from pydantic_ai import Agent

        facts = self._collected_facts(deps)
        try:
            summarizer = Agent(
                self._model,
                output_type=str,
                system_prompt="Summarize the security testing performed and the bugs proven. Be concise and factual.",
            )
            result = await asyncio.wait_for(
                summarizer.run(facts),
                timeout=min(60, max(15, agent_cfg.timeout // 10)),
            )
            return result.output or facts
        except Exception:
            return facts

    @staticmethod
    def _collected_facts(deps: AgentDeps) -> str:
        parts = [
            f"Actions taken: {deps.tool_calls}.",
            f"Bugs saved: {len(deps.findings)}.",
        ]
        for f in deps.findings:
            parts.append(f"- [{f.severity.value}] {f.title} @ {f.target or f.affected_url}")
        if deps.pocs:
            parts.append(f"PoCs recorded: {len(deps.pocs)}.")
        if deps.exploit_plan:
            parts.append(f"Dry-run exploit-plan steps: {len(deps.exploit_plan)}.")
        return "\n".join(parts)


def build_allowlist_hosts(targets: list[str], extra: list[str] | None = None) -> set[str]:
    """Derive the host allowlist from scan targets (+ optional discovered hosts)."""
    hosts = extract_hosts(*targets)
    # Bare hostnames/IPs that aren't URLs won't be caught by extract_hosts's URL
    # path; add the raw tokens too.
    for t in targets:
        tok = t.strip().lower()
        if tok and "/" not in tok and " " not in tok:
            hosts.add(tok.split(":")[0])
    if extra:
        hosts |= extract_hosts(*extra)
        hosts |= {e.strip().lower() for e in extra if e.strip()}
    return {h for h in hosts if h}
