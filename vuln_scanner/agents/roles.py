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

Role specialization prompt text lives in ``templates/roles/*.jinja`` rather than
in Python string literals.
"""

from pydantic import BaseModel, Field

from vuln_scanner.agents.models import AgentKind
from vuln_scanner.agents.prompts import system_prompt_for
from vuln_scanner.agents.templating import render_template

LEAD_ROLE = "lead"


class AgentRole(BaseModel):
    """A specialist profile the supervisor can instantiate as an agent."""

    name: str = Field(description="Unique role name.")
    kind: AgentKind = Field(description="Enforced safety profile the role runs under.")
    description: str = Field(description="Short human-readable summary of the role's focus.")
    system_prompt: str = Field(description="Full system prompt for an agent in this role.")
    can_delegate: bool = Field(False, description="Whether the role may post tasks for other roles.")


_LEAD_FOCUS = render_template("roles/lead.jinja")
_SPECIALIST_FOOTER = render_template("roles/specialist_footer.jinja")

# Role name → (enforced safety profile, short description).  The specialization
# prompt for each name is loaded from ``templates/roles/<name>.jinja``.
_SPECIALIST_SPECS: dict[str, tuple[AgentKind, str]] = {
    "recon": (AgentKind.BUG_BOUNTY, "Reconnaissance and attack-surface mapping."),
    "web": (AgentKind.BUG_BOUNTY, "Web-application vulnerability hunting."),
    "network": (AgentKind.BUG_BOUNTY, "Network and service enumeration."),
    "cloud": (AgentKind.BUG_BOUNTY, "Cloud and infrastructure posture."),
    "exploit": (AgentKind.PENTESTER, "Proof-of-concept exploitation of confirmed weaknesses."),
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
    for name, (kind, description) in _SPECIALIST_SPECS.items():
        focus = render_template(f"roles/{name}.jinja")
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
    return list(_SPECIALIST_SPECS)
