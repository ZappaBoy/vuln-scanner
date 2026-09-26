"""Role registry: safety-profile mapping and delegation permissions."""

from vuln_scanner.agents.models import AgentKind
from vuln_scanner.agents.roles import (
    LEAD_ROLE,
    builtin_roles,
    get_role,
    specialist_role_names,
)


def test_lead_is_bug_bounty_and_can_delegate():
    lead = get_role(LEAD_ROLE)
    assert lead is not None
    assert lead.kind == AgentKind.BUG_BOUNTY
    assert lead.can_delegate is True


def test_exploit_role_uses_pentester_profile():
    exploit = get_role("exploit")
    assert exploit is not None
    assert exploit.kind == AgentKind.PENTESTER


def test_specialists_cannot_delegate():
    for name in specialist_role_names():
        role = get_role(name)
        assert role is not None
        assert role.can_delegate is False


def test_lead_not_in_specialist_targets():
    assert LEAD_ROLE not in specialist_role_names()


def test_unknown_role_is_none():
    assert get_role("nope") is None
    assert get_role("") is None


def test_registry_is_copied():
    builtin_roles()["lead"].description = "mutated"
    assert get_role(LEAD_ROLE).description != "mutated"


def test_every_role_has_a_prompt():
    for role in builtin_roles().values():
        assert role.system_prompt.strip()
