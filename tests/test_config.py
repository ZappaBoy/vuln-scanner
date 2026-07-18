from argparse import Namespace

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.config.models import ReportFormat, ScanMode


def _args(**kwargs) -> Namespace:
    """Build a Namespace that matches what build_arg_parser() would produce."""
    # Parse empty args to get all defaults, then override with kwargs.
    base = build_arg_parser().parse_args([])
    for k, v in kwargs.items():
        setattr(base, k, v)
    return base


def test_defaults_when_no_source(monkeypatch, tmp_path):
    # Run from a temp dir so the project's config.toml is not picked up.
    monkeypatch.chdir(tmp_path)
    config = load_config(_args())
    assert config.scan.targets == []
    assert config.scan.mode == ScanMode.PASSIVE
    assert config.scan.timeout == 300
    assert ReportFormat.MARKDOWN in config.report.formats


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


def test_formats_cli_multi():
    config = load_config(_args(formats=["markdown", "html", "json"]))
    assert ReportFormat.MARKDOWN in config.report.formats
    assert ReportFormat.HTML in config.report.formats
    assert ReportFormat.JSON in config.report.formats


def test_no_llm_flag():
    config = load_config(_args(no_llm=True))
    assert config.llm.enabled is False


def test_llm_model_cli():
    config = load_config(_args(llm_model="gpt-4o"))
    assert config.llm.model == "gpt-4o"


def test_openai_api_key_fallback(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
    config = load_config(_args())
    assert config.llm.api_key == "sk-test-123"


def test_build_llm_config_valid():
    config = load_config(_args(llm_model="gpt-4o"))
    # inject a key manually so the config is "active"
    config.llm.api_key = "sk-test"
    config.llm.enabled = True
    llm = config.build_llm_config()
    llm.validate_active()  # should not raise


def test_build_llm_config_no_model_raises():
    import pytest
    config = load_config(_args())
    config.llm.api_key = "sk-test"
    config.llm.enabled = True
    llm = config.build_llm_config()
    with pytest.raises(ValueError):
        llm.validate_active()


def test_scan_auth_hoisted_from_toml(tmp_path):
    """[scan.auth] in config.toml must populate AppConfig.auth (top-level field)."""
    toml = tmp_path / "config.toml"
    toml.write_text(
        '[scan.auth]\nbearer_token = "toml-token"\n'
        '[scan.auth.cookies]\nsession = "abc"\n'
    )
    config = load_config(_args(config=str(toml)))
    assert config.auth.bearer_token == "toml-token"
    assert config.auth.cookies == {"session": "abc"}


def test_cli_auth_overrides_toml(tmp_path):
    toml = tmp_path / "config.toml"
    toml.write_text('[scan.auth]\nbearer_token = "toml-token"\n')
    config = load_config(_args(config=str(toml), auth_bearer="cli-token"))
    assert config.auth.bearer_token == "cli-token"
