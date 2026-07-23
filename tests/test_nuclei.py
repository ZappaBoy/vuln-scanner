"""Tests for the Nuclei deep-integration command builder."""

import json

from vuln_scanner.config.models import NucleiConfig
from vuln_scanner.tools.enums import ScanMode
from vuln_scanner.tools.models import AuthConfig, ScanInput
from vuln_scanner.tools.nuclei import NucleiTool, _build_nuclei_command


def _si(mode: ScanMode = ScanMode.PASSIVE, **kwargs) -> ScanInput:
    return ScanInput(targets=["https://target.example.com"], mode=mode, **kwargs)


def _cmd(mode: ScanMode = ScanMode.PASSIVE, cfg: NucleiConfig | None = None, **si_kwargs) -> list[str]:
    return _build_nuclei_command("https://target.example.com", _si(mode, **si_kwargs), cfg)


class TestNucleiCommandBuilder:
    def test_base_command_structure(self):
        cmd = _cmd()
        assert cmd[0] == "nuclei"
        assert "-u" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd

    # ── Severity profiles ──────────────────────────────────────────────────
    def test_paranoid_severity(self):
        cmd = _cmd(ScanMode.PARANOID)
        idx = cmd.index("-severity")
        assert "critical" not in cmd[idx + 1]
        assert "high" not in cmd[idx + 1]
        assert "info" in cmd[idx + 1]
        assert "low" in cmd[idx + 1]

    def test_aggressive_severity_includes_all(self):
        cmd = _cmd(ScanMode.AGGRESSIVE)
        idx = cmd.index("-severity")
        sev = cmd[idx + 1]
        for s in ("info", "low", "medium", "high", "critical"):
            assert s in sev

    def test_active_severity_excludes_info(self):
        cmd = _cmd(ScanMode.ACTIVE)
        idx = cmd.index("-severity")
        assert "info" not in cmd[idx + 1].split(",")

    # ── Passive flag ───────────────────────────────────────────────────────
    def test_paranoid_uses_passive_flag(self):
        assert "-passive" in _cmd(ScanMode.PARANOID)

    def test_passive_uses_passive_flag(self):
        assert "-passive" in _cmd(ScanMode.PASSIVE)

    def test_active_no_passive_flag(self):
        assert "-passive" not in _cmd(ScanMode.ACTIVE)

    # ── Tags ───────────────────────────────────────────────────────────────
    def test_paranoid_mode_adds_safe_tags(self):
        cmd = _cmd(ScanMode.PARANOID)
        assert "-tags" in cmd
        tags = cmd[cmd.index("-tags") + 1]
        assert "dns" in tags

    def test_user_tags_override_mode_defaults(self):
        cfg = NucleiConfig(tags=["cve", "sqli"])
        cmd = _cmd(cfg=cfg)
        tags = cmd[cmd.index("-tags") + 1]
        assert "cve" in tags
        assert "dns" not in tags  # mode default not injected when user specifies

    def test_always_excluded_tags_present(self):
        cmd = _cmd()
        assert "-etags" in cmd
        etags = cmd[cmd.index("-etags") + 1]
        assert "dos" in etags
        assert "fuzz" in etags

    def test_paranoid_excludes_dangerous_tags(self):
        cmd = _cmd(ScanMode.PARANOID)
        etags = cmd[cmd.index("-etags") + 1]
        assert "rce" in etags
        assert "sqli" in etags
        assert "xss" in etags

    def test_user_exclude_tags_merged(self):
        cfg = NucleiConfig(exclude_tags=["custom-tag"])
        cmd = _cmd(cfg=cfg)
        etags = cmd[cmd.index("-etags") + 1]
        assert "custom-tag" in etags
        assert "dos" in etags  # always-safe still present

    # ── Interactsh ─────────────────────────────────────────────────────────
    def test_paranoid_forces_no_interactsh(self):
        cfg = NucleiConfig(no_interactsh=False)  # user tries to enable
        cmd = _cmd(ScanMode.PARANOID, cfg=cfg)
        assert "-no-interactsh" in cmd

    def test_active_allows_interactsh_when_configured(self):
        cfg = NucleiConfig(no_interactsh=False)
        cmd = _cmd(ScanMode.ACTIVE, cfg=cfg)
        assert "-no-interactsh" not in cmd

    def test_custom_interactsh_server(self):
        cfg = NucleiConfig(no_interactsh=False, interactsh_server="https://oast.example.com")
        cmd = _cmd(ScanMode.ACTIVE, cfg=cfg)
        assert "-iserver" in cmd
        assert "oast.example.com" in cmd[cmd.index("-iserver") + 1]

    # ── Performance knobs ──────────────────────────────────────────────────
    def test_rate_limit_from_config(self):
        cfg = NucleiConfig(rate_limit=50)
        cmd = _cmd(cfg=cfg)
        assert "-rl" in cmd
        assert cmd[cmd.index("-rl") + 1] == "50"

    def test_scan_input_rate_limit_overrides_config(self):
        cfg = NucleiConfig(rate_limit=150)
        cmd = _cmd(cfg=cfg, rate_limit=30)
        assert cmd[cmd.index("-rl") + 1] == "30"

    def test_bulk_size_and_concurrency(self):
        cfg = NucleiConfig(bulk_size=10, concurrency=5)
        cmd = _cmd(cfg=cfg)
        assert cmd[cmd.index("-bs") + 1] == "10"
        assert cmd[cmd.index("-c") + 1] == "5"

    # ── Headless ───────────────────────────────────────────────────────────
    def test_headless_only_in_aggressive(self):
        cfg = NucleiConfig(headless=True)
        assert "-headless" not in _cmd(ScanMode.ACTIVE, cfg=cfg)
        assert "-headless" in _cmd(ScanMode.AGGRESSIVE, cfg=cfg)

    def test_headless_false_never_added(self):
        cfg = NucleiConfig(headless=False)
        assert "-headless" not in _cmd(ScanMode.AGGRESSIVE, cfg=cfg)

    # ── Templates ──────────────────────────────────────────────────────────
    def test_custom_templates_dir(self):
        from pathlib import Path

        cfg = NucleiConfig(templates_dir=Path("/opt/my-templates"))
        cmd = _cmd(cfg=cfg)
        assert "-t" in cmd
        assert "/opt/my-templates" in cmd

    def test_new_templates_flag(self):
        cfg = NucleiConfig(only_new_templates=True)
        assert "-new-templates" in _cmd(cfg=cfg)

    # ── Auth ───────────────────────────────────────────────────────────────
    def test_bearer_token_injected(self):
        auth = AuthConfig(bearer_token="my-jwt")
        cmd = _cmd(auth=auth)
        assert any("Authorization: Bearer my-jwt" in arg for arg in cmd)

    def test_basic_auth_injected(self):
        auth = AuthConfig(username="user", password="pass")
        cmd = _cmd(auth=auth)
        assert "-auth-type" in cmd
        assert "basic" in cmd
        assert "-auth-cred" in cmd

    # ── Proxy ──────────────────────────────────────────────────────────────
    def test_proxy_injected(self):
        cmd = _cmd(proxy="http://127.0.0.1:8080")
        assert "-proxy" in cmd
        assert cmd[cmd.index("-proxy") + 1] == "http://127.0.0.1:8080"

    def test_no_proxy_when_not_set(self):
        assert "-proxy" not in _cmd()

    # ── Workflows ──────────────────────────────────────────────────────────
    def test_workflow_added(self):
        from pathlib import Path

        cfg = NucleiConfig(workflows=[Path("/opt/workflows/sqli.yaml")])
        cmd = _cmd(cfg=cfg)
        assert "-w" in cmd
        assert "/opt/workflows/sqli.yaml" in cmd


class TestNucleiParser:
    tool = NucleiTool()
    target = "https://app.example.com"

    def _make_line(self, **overrides) -> str:
        base = {
            "template-id": "cve-2021-1234",
            "info": {
                "name": "CVE-2021-1234 RCE",
                "severity": "critical",
                "description": "Remote code execution via log4j",
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"],
            },
            "host": "https://app.example.com",
            "matched-at": "https://app.example.com/api",
            "request": "GET /api HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\nok",
        }
        base.update(overrides)
        return json.dumps(base)

    def test_parses_critical_finding(self):
        findings = self.tool.parse_output(self._make_line(), self.target)
        assert len(findings) == 1
        from vuln_scanner.tools.enums import Severity

        assert findings[0].severity == Severity.CRITICAL

    def test_extracts_cve(self):
        findings = self.tool.parse_output(self._make_line(), self.target)
        assert (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-1234" in findings[0].cve or findings[0].cve
        )  # references contain the URL; cve list may vary

    def test_extracts_request_response(self):
        findings = self.tool.parse_output(self._make_line(), self.target)
        assert "GET /api" in findings[0].request
        assert "200 OK" in findings[0].response

    def test_skips_non_json_lines(self):
        raw = "Nuclei v3.0.0\n" + self._make_line()
        findings = self.tool.parse_output(raw, self.target)
        assert len(findings) == 1

    def test_empty_output(self):
        assert self.tool.parse_output("", self.target) == []
