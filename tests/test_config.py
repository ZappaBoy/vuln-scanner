import os
import tomllib
from argparse import Namespace
from pathlib import Path

import pytest

from vuln_scanner.config.loader import load_config
from vuln_scanner.config.models import AppConfig, ScanMode


def _args(**kwargs) -> Namespace:
    defaults = dict(
        config=None, targets=None, timeout=None, max_concurrent=None,
        mode=None, include_categories=None, exclude_categories=None,
        include_tools=None, exclude_tools=None, format=None,
        output_dir=None, defectdojo_url=None, defectdojo_api_key=None,
        verbose=False,
    )
    defaults.update(kwargs)
    return Namespace(**defaults)


def test_defaults_when_no_source():
    config = load_config(_args())
    assert config.scan.targets == []
    assert config.scan.mode == ScanMode.PASSIVE
    assert config.scan.timeout == 300
    assert config.report.format.value == "markdown"


def test_cli_targets_override():
    config = load_config(_args(targets=["192.168.1.1", "10.0.0.0/8"]))
    assert config.scan.targets == ["192.168.1.1", "10.0.0.0/8"]


def test_cli_mode_override():
    config = load_config(_args(mode="aggressive"))
    assert config.scan.mode == ScanMode.AGGRESSIVE


def test_cli_mode_default_is_passive():
    config = load_config(_args())
    assert config.scan.mode == ScanMode.PASSIVE


def test_env_targets_override(monkeypatch):
    monkeypatch.setenv("VS_TARGETS", '["172.16.0.1"]')
    config = load_config(_args())
    assert "172.16.0.1" in config.scan.targets


def test_env_mode_override(monkeypatch):
    monkeypatch.setenv("VS_MODE", "active")
    config = load_config(_args())
    assert config.scan.mode == ScanMode.ACTIVE


def test_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("VS_MODE", "active")
    config = load_config(_args(mode="paranoid"))
    assert config.scan.mode == ScanMode.PARANOID


def test_toml_file_loaded(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[scan]\ntargets = ["1.2.3.4"]\nmode = "aggressive"\n')
    config = load_config(_args(config=str(cfg)))
    assert config.scan.targets == ["1.2.3.4"]
    assert config.scan.mode == ScanMode.AGGRESSIVE


def test_cli_overrides_toml(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[scan]\nmode = "aggressive"\n')
    config = load_config(_args(config=str(cfg), mode="passive"))
    assert config.scan.mode == ScanMode.PASSIVE


def test_tool_filter_include():
    config = load_config(_args(include_tools=["nmap"]))
    assert config.tools.include == ["nmap"]


def test_tool_filter_exclude():
    config = load_config(_args(exclude_tools=["nikto"]))
    assert config.tools.exclude == ["nikto"]
