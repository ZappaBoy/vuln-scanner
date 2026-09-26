"""M3/#9 — OobSession subprocess lifecycle against a fake interactsh-client.

The fake is a harmless shell script (echoes a domain + a JSON interaction), so
this exercises the real Popen + reader-thread + parsing path without any network
or real security tool.
"""

import time
from pathlib import Path

import pytest

from vuln_scanner.agents.oob import OobSession

_FAKE = """#!/bin/sh
echo "[INF] Listing 1 payload for OOB Testing"
echo "abcdefghij1234567890kl.oast.pro"
echo '{"protocol":"dns","remote-address":"9.9.9.9","raw-request":"q","timestamp":"t"}'
sleep 2
"""


def _install_fake(tmp_path: Path, monkeypatch) -> None:
    binp = tmp_path / "interactsh-client"
    binp.write_text(_FAKE)
    binp.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")


def test_session_starts_and_captures_domain(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _install_fake(tmp_path, monkeypatch)
    session = OobSession()
    try:
        assert session.start(register_timeout=5.0) is True
        assert session.available is True
        assert session.domain == "abcdefghij1234567890kl.oast.pro"
    finally:
        session.stop()


def test_session_check_parses_interactions(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _install_fake(tmp_path, monkeypatch)
    session = OobSession()
    try:
        assert session.start(register_timeout=5.0) is True
        time.sleep(0.5)  # let the reader thread drain the JSON line
        interactions = session.check()
        assert len(interactions) == 1
        assert interactions[0]["protocol"] == "dns"
        assert interactions[0]["source"] == "9.9.9.9"
    finally:
        session.stop()


def test_session_unavailable_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    _install_fake(tmp_path, monkeypatch)
    session = OobSession()
    assert session.start(register_timeout=2.0) is False
    assert session.available is False


def test_session_unavailable_when_binary_missing(monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    monkeypatch.setenv("PATH", "/nonexistent-dir-xyz")
    session = OobSession()
    assert session.start(register_timeout=2.0) is False
    assert session.available is False


def test_stop_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("VS_IN_CONTAINER", "1")
    _install_fake(tmp_path, monkeypatch)
    session = OobSession()
    session.start(register_timeout=5.0)
    session.stop()
    session.stop()  # second call must not raise


@pytest.mark.parametrize("in_container", [True, False])
def test_start_never_raises(tmp_path, monkeypatch, in_container):
    if in_container:
        monkeypatch.setenv("VS_IN_CONTAINER", "1")
    else:
        monkeypatch.delenv("VS_IN_CONTAINER", raising=False)
    session = OobSession(server="http://oast.example", token="tok")
    # No fake installed; must degrade gracefully regardless.
    assert session.start(register_timeout=1.0) in (True, False)
    session.stop()
