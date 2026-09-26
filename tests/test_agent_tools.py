"""M3 — agent tool implementations + OOB parsers."""

from pathlib import Path

from vuln_scanner.agents.agent_tools import (
    http_request,
    list_tools,
    note,
    oob_get_callback,
    recall,
    record_poc,
    run_code,
    run_tool,
    save_bug,
)
from vuln_scanner.agents.audit import ActionLog
from vuln_scanner.agents.deps import AgentDeps
from vuln_scanner.agents.models import AgentConfig, AgentKind, AgentsConfig
from vuln_scanner.agents.oob import parse_callback_domain, parse_interaction
from vuln_scanner.scope import ScopeValidator


def _deps(
    tmp_path,
    *,
    kind=AgentKind.BUG_BOUNTY,
    include=None,
    allowlist=None,
    live_exploit=False,
    max_tool_calls=40,
    deadline=None,
) -> AgentDeps:
    scope = ScopeValidator(include=include or [], exclude=[], strict=False)
    agent = AgentConfig(name="hunter", kind=kind, max_tool_calls=max_tool_calls)
    return AgentDeps(
        agent=agent,
        agents_cfg=AgentsConfig(),
        scope=scope,
        audit=ActionLog(tmp_path, "hunter"),
        artifact_dir=Path(tmp_path),
        allowlist=set(allowlist or []),
        live_exploit_allowed=live_exploit,
        deadline=deadline,
    )


# ── precheck / ceilings ───────────────────────────────────────────────────────


def test_run_tool_unknown_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "no_such_tool", ["-x"], target="t.lab")
    assert "Unknown tool" in out["error"]


def test_ceiling_blocks_further_calls(tmp_path):
    deps = _deps(tmp_path, max_tool_calls=0)
    out = run_tool(deps, "nmap", ["-sV"], target="t.lab")
    assert "ceiling" in out["error"].lower()


def test_denied_tool(tmp_path):
    deps = _deps(tmp_path)
    deps.agent.denied_tools = ["run_code"]
    out = run_code(deps, "python", "print(1)")
    assert "denied" in out["error"].lower()


# ── run_tool guards ───────────────────────────────────────────────────────────


def test_run_tool_refuses_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, include=["t.lab"])
    out = run_tool(deps, "nmap", ["-sV", "evil.example.com"], target="evil.example.com")
    assert "out of scope" in out["error"].lower()


def test_run_tool_refuses_denylisted_args(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "nmap", ["-oN", "/etc/shadow", "t.lab"], target="t.lab")
    assert "Refused" in out["error"]


def test_run_tool_refuses_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = run_tool(deps, "nmap", ["-sV", "t.lab"], target="t.lab")
    assert "container" in out["error"].lower()


# ── run_code dry-run gate ─────────────────────────────────────────────────────


def test_pentester_dry_run_records_plan(tmp_path):
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, live_exploit=False)
    out = run_code(deps, "python", "print('exploit attempt')")
    assert out["executed"] is False
    assert deps.exploit_plan and "exploit attempt" in deps.exploit_plan[0]


def test_pentester_live_executes(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, live_exploit=True)
    out = run_code(deps, "python", "print('poc-live-99')")
    assert out["executed"] is True
    assert "poc-live-99" in out["stdout"]


def test_bug_bounty_executes_benign_code(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path)
    out = run_code(deps, "python", "print('bb-proof-7')")
    assert out["executed"] is True
    assert "bb-proof-7" in out["stdout"]


def test_run_code_scope_check_on_host_literal(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    deps = _deps(tmp_path, include=["t.lab"])
    out = run_code(deps, "python", "import urllib.request; urllib.request.urlopen('http://evil.example.com')")
    assert "out of scope" in out["error"].lower()


# ── save_bug / record_poc ─────────────────────────────────────────────────────


def test_save_bug_appends(tmp_path):
    deps = _deps(tmp_path)
    msg = save_bug(
        deps,
        title="Reflected XSS in q param",
        severity="high",
        target="t.lab",
        affected_param="q",
        reproduction_steps=["visit /?q=<script>", "observe alert"],
    )
    assert "Saved bug" in msg
    assert len(deps.findings) == 1
    f = deps.findings[0]
    assert f.severity.value == "high"
    assert f.discovered_by == "hunter"
    assert f.affected_param == "q"


def test_record_poc_writes_script(tmp_path):
    deps = _deps(tmp_path)
    msg = record_poc(
        deps,
        finding_title="SSRF",
        language="python",
        description="fetch internal metadata",
        script="print('poc')",
        verdict="confirmed",
    )
    assert "agent-poc-001" in msg
    assert len(deps.pocs) == 1
    assert Path(deps.pocs[0].script_path).exists()


# ── list_tools ────────────────────────────────────────────────────────────────


def test_list_tools_returns_string(tmp_path):
    deps = _deps(tmp_path)
    out = list_tools(deps)
    assert isinstance(out, str)


# ── OOB ───────────────────────────────────────────────────────────────────────


def test_oob_unavailable_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    deps = _deps(tmp_path)
    out = oob_get_callback(deps)
    assert "container" in out.lower()


def test_parse_callback_domain():
    text = "[INF] Listing 1 payload for OOB Testing\nc8r1abcdefgh12345678ij.oast.pro"
    assert parse_callback_domain(text) == "c8r1abcdefgh12345678ij.oast.pro"


def test_parse_interaction_valid():
    line = '{"protocol":"dns","remote-address":"1.2.3.4","raw-request":"q","timestamp":"t"}'
    rec = parse_interaction(line)
    assert rec is not None
    assert rec["protocol"] == "dns"
    assert rec["source"] == "1.2.3.4"


def test_parse_interaction_ignores_noise():
    assert parse_interaction("not json") is None
    assert parse_interaction('{"no":"protocol"}') is None


# ── http_request ──────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal requests.Response stand-in for http_request tests."""

    def __init__(self, status_code=200, reason="OK", headers=None, body=b"", url="http://t.lab/"):
        self.status_code = status_code
        self.reason = reason
        self.headers = headers or {"Content-Type": "text/html"}
        self.encoding = "utf-8"
        self.url = url
        self._body = body

    def iter_content(self, chunk_size=4096):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        pass


def _patch_requests(monkeypatch, resp=None, exc=None):
    import requests

    calls = {}

    def _fake_request(method, url, **kwargs):
        calls["method"] = method
        calls["url"] = url
        calls["kwargs"] = kwargs
        if exc is not None:
            raise exc
        return resp

    monkeypatch.setattr(requests, "request", _fake_request)
    return calls


def test_http_request_success(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    calls = _patch_requests(
        monkeypatch,
        resp=_FakeResp(status_code=200, body=b"<html>marker42</html>"),
    )
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "GET", "http://t.lab/path?x=1", headers={"X-Test": "1"})
    assert out["status_code"] == 200
    assert "marker42" in out["body"]
    assert out["request"].startswith("GET /path?x=1 HTTP/1.1")
    assert "Host: t.lab" in out["request"]
    assert "HTTP/1.1 200 OK" in out["response"]
    # scope-check must have short-circuited to the real request
    assert calls["method"] == "GET"
    assert calls["kwargs"]["verify"] is False


def test_http_request_refuses_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _patch_requests(monkeypatch, resp=_FakeResp())
    deps = _deps(tmp_path, include=["t.lab"])
    out = http_request(deps, "GET", "http://evil.example.com/")
    assert "out of scope" in out["error"].lower()


def test_http_request_refuses_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    _patch_requests(monkeypatch, resp=_FakeResp())
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "GET", "http://t.lab/")
    assert "container" in out["error"].lower()


def test_http_request_denylisted_body(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _patch_requests(monkeypatch, resp=_FakeResp())
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "POST", "http://t.lab/", body="cmd=mkfs /dev/sda")
    assert "Refused" in out["error"]


def test_http_request_unsupported_method(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _patch_requests(monkeypatch, resp=_FakeResp())
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "TRACE", "http://t.lab/")
    assert "Unsupported HTTP method" in out["error"]


def test_http_request_ceiling(tmp_path):
    deps = _deps(tmp_path, max_tool_calls=0)
    out = http_request(deps, "GET", "http://t.lab/")
    assert "ceiling" in out["error"].lower()


def test_http_request_pentester_dry_run_mutating(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    calls = _patch_requests(monkeypatch, resp=_FakeResp())
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, allowlist={"t.lab"}, live_exploit=False)
    out = http_request(deps, "POST", "http://t.lab/login", body="u=a&p=b")
    assert out["executed"] is False
    assert "dry-run" in out["note"].lower()
    assert deps.exploit_plan  # recorded, not sent
    assert "method" not in calls  # requests.request was never called


def test_http_request_pentester_safe_method_sent(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    calls = _patch_requests(monkeypatch, resp=_FakeResp(body=b"ok"))
    deps = _deps(tmp_path, kind=AgentKind.PENTESTER, allowlist={"t.lab"}, live_exploit=False)
    out = http_request(deps, "GET", "http://t.lab/")
    assert out["status_code"] == 200
    assert calls["method"] == "GET"


def test_http_request_network_error(tmp_path, monkeypatch):
    import requests

    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _patch_requests(monkeypatch, exc=requests.ConnectionError("boom"))
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "GET", "http://t.lab/")
    assert "Request failed" in out["error"]


def test_http_request_body_truncated(tmp_path, monkeypatch):
    from vuln_scanner.agents.agent_tools import _MAX_RESP_BYTES

    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _patch_requests(monkeypatch, resp=_FakeResp(body=b"A" * (_MAX_RESP_BYTES + 100)))
    deps = _deps(tmp_path, allowlist={"t.lab"})
    out = http_request(deps, "GET", "http://t.lab/big")
    assert out["truncated"] is True
    assert len(out["body"]) == _MAX_RESP_BYTES
    assert "truncated" in out["response"].lower()


# ── note / recall (scratchpad) ──────────────────────────────────────────────────


def test_note_appends_and_increments_seq(tmp_path):
    deps = _deps(tmp_path)
    assert note(deps, "found /admin endpoint", tag="recon") == "Noted #1 [recon]"
    assert note(deps, "param id looks injectable") == "Noted #2"
    assert len(deps.notes) == 2
    assert deps.notes[0] == {
        "seq": 1,
        "tag": "recon",
        "text": "found /admin endpoint",
        "ts": deps.notes[0]["ts"],
    }
    assert deps.tool_calls == 2  # each note counts against the ceiling


def test_note_ignores_empty_text(tmp_path):
    deps = _deps(tmp_path)
    out = note(deps, "   ")
    assert "Empty note" in out
    assert deps.notes == []


def test_recall_returns_all_notes(tmp_path):
    deps = _deps(tmp_path)
    note(deps, "a", tag="recon")
    note(deps, "b")
    out = recall(deps)
    assert out == "#1 [recon]: a\n#2: b"


def test_recall_filters_by_tag(tmp_path):
    deps = _deps(tmp_path)
    note(deps, "a", tag="recon")
    note(deps, "b", tag="probe")
    note(deps, "c", tag="recon")
    out = recall(deps, tag="recon")
    assert "a" in out and "c" in out and "b" not in out


def test_recall_empty_state(tmp_path):
    deps = _deps(tmp_path)
    assert "No notes recorded" in recall(deps)
    assert "tagged [x]" in recall(deps, tag="x")


def test_note_ceiling_blocks(tmp_path):
    deps = _deps(tmp_path, max_tool_calls=0)
    out = note(deps, "should be blocked")
    assert "ceiling" in out.lower()
    assert deps.notes == []


def test_recall_ceiling_blocks(tmp_path):
    deps = _deps(tmp_path, max_tool_calls=0)
    out = recall(deps)
    assert "ceiling" in out.lower()


def test_note_respects_allow_deny_filter(tmp_path):
    deps = _deps(tmp_path)
    deps.agent.denied_tools = ["note"]
    out = note(deps, "x")
    assert "denied" in out.lower()
    assert deps.notes == []


def test_note_count_cap_enforced(tmp_path):
    from vuln_scanner.agents.agent_tools import _MAX_NOTES

    deps = _deps(tmp_path, max_tool_calls=_MAX_NOTES + 5)
    for _ in range(_MAX_NOTES):
        note(deps, "x")
    assert len(deps.notes) == _MAX_NOTES
    out = note(deps, "one too many")
    assert "full" in out.lower()
    assert len(deps.notes) == _MAX_NOTES


def test_note_text_truncated(tmp_path):
    from vuln_scanner.agents.agent_tools import _MAX_NOTE_LEN

    deps = _deps(tmp_path)
    note(deps, "B" * (_MAX_NOTE_LEN + 500))
    stored = deps.notes[0]["text"]
    assert "truncated" in stored
    assert stored.startswith("B" * _MAX_NOTE_LEN)


def test_note_persists_to_jsonl(tmp_path):
    import json

    deps = _deps(tmp_path)
    note(deps, "endpoint /admin", tag="recon")
    note(deps, "param id")
    notes_file = Path(tmp_path) / "hunter.notes.jsonl"
    assert notes_file.exists()
    lines = notes_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec == {"seq": 1, "tag": "recon", "text": "endpoint /admin", "ts": rec["ts"]}
    # empty and capped notes are not persisted
    note(deps, "   ")
    assert len(notes_file.read_text(encoding="utf-8").splitlines()) == 2
