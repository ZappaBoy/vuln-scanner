"""Default, overridable system prompts for the agent profiles.

The prompt text lives in ``templates/prompts/*.jinja`` rather than in Python
string literals.  An agent's ``system_prompt`` config field, when set, replaces
the built-in default returned by :func:`system_prompt_for`.
"""

from vuln_scanner.agents.models import AgentKind
from vuln_scanner.agents.templating import render_template

BUG_BOUNTY_SYSTEM = render_template("prompts/bug_bounty.jinja")
PENTESTER_SYSTEM = render_template("prompts/pentester.jinja")

_SYSTEM_PROMPTS: dict[AgentKind, str] = {
    AgentKind.BUG_BOUNTY: BUG_BOUNTY_SYSTEM,
    AgentKind.PENTESTER: PENTESTER_SYSTEM,
}


def system_prompt_for(kind: AgentKind) -> str:
    return _SYSTEM_PROMPTS.get(kind, BUG_BOUNTY_SYSTEM)
