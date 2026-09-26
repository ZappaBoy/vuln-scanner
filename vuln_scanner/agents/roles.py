"""Specialist agent roles for a multi-agent engagement.

A role bundles a specialization (coordination, recon, web, network, cloud,
exploitation) with the safety profile it runs under (:class:`AgentKind`) and
whether it is permitted to delegate work to other roles.

The safety profile is the load-bearing field.  A role mapped to
``AgentKind.PENTESTER`` inherits the dry-run exploitation gate; a
``AgentKind.BUG_BOUNTY`` role can never execute a mutating action regardless of
what its prompt says.  Prompt text is advisory; the kind is enforced in code
(see :mod:`vuln_scanner.agents.agent_tools`).  Only roles with
``can_delegate=True`` may post tasks for other roles; this is likewise enforced
at the tool layer, not merely requested in the prompt.
"""

from pydantic import BaseModel

from vuln_scanner.agents.models import AgentKind
from vuln_scanner.agents.prompts import system_prompt_for

LEAD_ROLE = "lead"


class AgentRole(BaseModel):
    """A specialist profile the supervisor can instantiate as an agent."""

    name: str
    kind: AgentKind
    description: str
    system_prompt: str
    can_delegate: bool = False


_LEAD_FOCUS = """\

ROLE SPECIALIZATION: Lead coordinator.
You do not scan or exploit directly.  Read the assessment and the shared
blackboard, decompose the objective into concrete tasks, and delegate each to
the most suitable specialist role (recon, web, network, cloud, exploit) with
post_task.  Prefer a handful of sharp, well-scoped tasks over many vague ones.
As specialists report back, read shared state and post follow-up tasks to chase
promising leads.  Stop delegating and summarize once the objective is covered
or the task budget is nearly spent.
"""

_SPECIALIST_FOOTER = """\
Publish anything another specialist could use (new hosts, endpoints, params,
credentials) to the shared blackboard with share_finding / record_asset /
record_credential.  Read shared state before you start so you do not repeat
work already done by another agent.
"""

_ROLE_FOCUS: dict[str, tuple[AgentKind, str, str]] = {
    "recon": (
        AgentKind.BUG_BOUNTY,
        "Reconnaissance and attack-surface mapping.",
        "ROLE SPECIALIZATION: Reconnaissance. Enumerate subdomains, live hosts, "
        "endpoints, parameters, and technologies. Do not test for vulnerabilities; "
        "map the surface and publish assets for the other specialists.",
    ),
    "web": (
        AgentKind.BUG_BOUNTY,
        "Web-application vulnerability hunting.",
        "ROLE SPECIALIZATION: Web application testing. Probe the mapped web "
        "surface for injection, access-control, and misconfiguration bugs, and "
        "prove each with request/response evidence.",
    ),
    "network": (
        AgentKind.BUG_BOUNTY,
        "Network and service enumeration.",
        "ROLE SPECIALIZATION: Network services. Enumerate open ports and service "
        "versions, identify exposed or misconfigured services, and flag weak "
        "authentication surfaces for the exploit specialist.",
    ),
    "cloud": (
        AgentKind.BUG_BOUNTY,
        "Cloud and infrastructure posture.",
        "ROLE SPECIALIZATION: Cloud posture. Inspect cloud storage, IAM, and "
        "infrastructure exposure for misconfigurations that leak data or grant "
        "unintended access.",
    ),
    "exploit": (
        AgentKind.PENTESTER,
        "Proof-of-concept exploitation of confirmed weaknesses.",
        "ROLE SPECIALIZATION: Exploitation. Take confirmed weaknesses from shared "
        "state and build a minimal, non-destructive proof of concept. The dry-run "
        "gate applies: without live-exploitation clearance you record an exploit "
        "plan rather than executing it.",
    ),
}


def _build_registry() -> dict[str, AgentRole]:
    roles: dict[str, AgentRole] = {
        LEAD_ROLE: AgentRole(
            name=LEAD_ROLE,
            kind=AgentKind.BUG_BOUNTY,
            description="Coordinator that plans and delegates to specialists.",
            system_prompt=system_prompt_for(AgentKind.BUG_BOUNTY) + _LEAD_FOCUS,
            can_delegate=True,
        )
    }
    for name, (kind, description, focus) in _ROLE_FOCUS.items():
        roles[name] = AgentRole(
            name=name,
            kind=kind,
            description=description,
            system_prompt=system_prompt_for(kind) + "\n" + focus + "\n" + _SPECIALIST_FOOTER,
            can_delegate=False,
        )
    return roles


_REGISTRY = _build_registry()


def builtin_roles() -> dict[str, AgentRole]:
    """Return deep copies of the built-in roles.

    Copies, not references: a caller must not be able to mutate shared role
    state (its enforced ``kind`` or ``can_delegate``) through the registry.
    """
    return {name: role.model_copy(deep=True) for name, role in _REGISTRY.items()}


def get_role(name: str) -> AgentRole | None:
    role = _REGISTRY.get((name or "").strip())
    return role.model_copy(deep=True) if role is not None else None


def specialist_role_names() -> list[str]:
    """Delegatable target roles (everything except the lead)."""
    return [name for name in _ROLE_FOCUS]
