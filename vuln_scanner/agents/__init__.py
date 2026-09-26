"""Agentic LLM layer — bug-bounty and pentester agents (Pydantic AI).

Runs AFTER tool execution and the static LLM analysis pass, container-only
(`VS_IN_CONTAINER`).  Agents may drive existing tools with custom arguments and
execute sandboxed code to prove or exploit findings, subject to hard scope,
denylist, sandbox, and usage-limit guards.

This package's ``models`` module is import-light (no openai / pydantic-ai) so it
can be referenced from config.  The heavy runtime lives in ``runner`` and
``agent_tools`` and is imported lazily.
"""
