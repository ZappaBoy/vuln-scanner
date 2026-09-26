"""EngagementState blackboard: dedup, caps, filtering, persistence, thread-safety."""

import json
import threading
from pathlib import Path

from vuln_scanner.agents.blackboard import Credential, EngagementState
from vuln_scanner.agents.models import AgentFinding
from vuln_scanner.tools.enums import Severity


def _finding(title="XSS", url="https://t.lab/a", sev=Severity.HIGH, by="web"):
    return AgentFinding(title=title, severity=sev, affected_url=url, discovered_by=by)


# ── Assets ────────────────────────────────────────────────────────────────────


def test_add_asset_dedups_case_insensitively():
    state = EngagementState()
    assert state.add_asset("URL", "https://t.lab/a", source="recon") is True
    assert state.add_asset("url", "https://t.lab/a", source="web") is False
    assert state.counts()["assets"] == 1


def test_add_asset_rejects_empty():
    state = EngagementState()
    assert state.add_asset("url", "   ") is False
    assert state.counts()["assets"] == 0


def test_assets_filter_by_type_and_order():
    state = EngagementState()
    state.add_asset("url", "https://t.lab/1")
    state.add_asset("subdomain", "api.t.lab")
    state.add_asset("url", "https://t.lab/2")
    urls = state.assets("url")
    assert [a.value for a in urls] == ["https://t.lab/1", "https://t.lab/2"]
    assert len(state.assets()) == 3


# ── Findings ────────────────────────────────────────────────────────────────────


def test_add_finding_dedups_on_title_and_target():
    state = EngagementState()
    assert state.add_finding(_finding()) is True
    assert state.add_finding(_finding()) is False
    assert state.add_finding(_finding(url="https://t.lab/b")) is True
    assert state.counts()["findings"] == 2


# ── Credentials ──────────────────────────────────────────────────────────────────


def test_add_credential_dedup():
    state = EngagementState()
    c = Credential(kind="password", username="admin", secret="p", host="t.lab", source="net")
    assert state.add_credential(c) is True
    assert state.add_credential(c) is False
    assert state.counts()["credentials"] == 1
    assert state.credentials()[0].secret == "p"


# ── Persistence ──────────────────────────────────────────────────────────────────


def test_events_written_but_secret_never_logged(tmp_path: Path):
    state = EngagementState(run_dir=tmp_path)
    state.add_asset("url", "https://t.lab/a", source="recon")
    state.add_finding(_finding())
    state.add_credential(Credential(kind="password", username="admin", secret="TOPSECRET", host="t.lab"))

    log_path = tmp_path / "blackboard" / "events.jsonl"
    assert log_path.exists()
    lines = [json.loads(ln) for ln in log_path.read_text().splitlines()]
    kinds = {ln["kind"] for ln in lines}
    assert kinds == {"asset", "finding", "credential"}
    # The credential secret must never reach the on-disk event log.
    assert "TOPSECRET" not in log_path.read_text()


def test_no_run_dir_means_no_event_log(tmp_path: Path):
    state = EngagementState()
    state.add_asset("url", "https://t.lab/a")
    assert not (tmp_path / "blackboard").exists()


# ── Caps ─────────────────────────────────────────────────────────────────────────


def test_credential_cap(monkeypatch):
    import vuln_scanner.agents.blackboard as bbmod

    monkeypatch.setattr(bbmod, "_MAX_CREDENTIALS", 2)
    state = EngagementState()
    assert state.add_credential(Credential(kind="k", secret="1")) is True
    assert state.add_credential(Credential(kind="k", secret="2")) is True
    assert state.add_credential(Credential(kind="k", secret="3")) is False


# ── Thread-safety ─────────────────────────────────────────────────────────────────


def test_concurrent_writers_are_consistent():
    state = EngagementState()

    def worker(base: int):
        for i in range(200):
            state.add_asset("url", f"https://t.lab/{base}-{i}")

    threads = [threading.Thread(target=worker, args=(b,)) for b in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert state.counts()["assets"] == 8 * 200
