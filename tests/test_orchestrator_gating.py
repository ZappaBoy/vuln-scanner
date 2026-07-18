"""Tests for orchestrator target-type gating and per-target auth — mocked subprocess."""


from vuln_scanner.config.models import AppConfig, ScanConfig
from vuln_scanner.orchestrator import ScanOrchestrator
from vuln_scanner.tools.enums import ScanStatus, TargetType
from vuln_scanner.tools.models import AuthConfig, Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool


class _MockWebTool(AbstractTool):
    name: str = "mock_web"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    _call_count: int = 0

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _MockWebTool._call_count += 1
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS)


class _MockNetTool(AbstractTool):
    name: str = "mock_net"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})
    _call_count: int = 0

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _MockNetTool._call_count += 1
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS)


def _config_with(targets: list[str]) -> AppConfig:
    cfg = AppConfig()
    cfg.scan = ScanConfig(targets=targets, max_concurrent=1)
    return cfg


class TestOrchestratorGating:
    def setup_method(self):
        _MockWebTool._call_count = 0
        _MockNetTool._call_count = 0

    def test_web_tool_only_runs_on_url(self):
        cfg = _config_with(["http://example.com", "192.168.1.1", "/path/to/code"])
        web = _MockWebTool()
        orc = ScanOrchestrator(config=cfg, tools=[web])
        results = orc.run()
        targets_run = {r.target for r in results}
        assert "http://example.com" in targets_run
        assert "192.168.1.1" not in targets_run
        assert "/path/to/code" not in targets_run

    def test_net_tool_only_runs_on_host_and_ip(self):
        cfg = _config_with(["http://example.com", "192.168.1.1", "example.com"])
        net = _MockNetTool()
        orc = ScanOrchestrator(config=cfg, tools=[net])
        results = orc.run()
        targets_run = {r.target for r in results}
        assert "192.168.1.1" in targets_run
        assert "example.com" in targets_run
        assert "http://example.com" not in targets_run

    def test_mixed_tools_run_on_correct_targets(self):
        cfg = _config_with(["http://example.com", "192.168.1.1"])
        web = _MockWebTool()
        net = _MockNetTool()
        orc = ScanOrchestrator(config=cfg, tools=[web, net])
        results = orc.run()
        tool_target_pairs = {(r.tool, r.target) for r in results}
        assert ("mock_web", "http://example.com") in tool_target_pairs
        assert ("mock_net", "192.168.1.1") in tool_target_pairs
        assert ("mock_web", "192.168.1.1") not in tool_target_pairs
        assert ("mock_net", "http://example.com") not in tool_target_pairs


class _AuthCapturingTool(AbstractTool):
    """Records the auth it received so tests can inspect per-target resolution."""
    name: str = "auth_capture"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    captured_auth: dict[str, AuthConfig] = {}

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _AuthCapturingTool.captured_auth[target] = scan_input.auth
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS)


def _config_with_auth(targets: list[str], auth: AuthConfig) -> AppConfig:
    cfg = AppConfig()
    cfg.scan = ScanConfig(targets=targets, max_concurrent=1)
    cfg.auth = auth
    return cfg


class TestOrchestratorPerTargetAuth:
    def setup_method(self):
        _AuthCapturingTool.captured_auth = {}

    def test_global_auth_used_when_no_per_target_override(self):
        global_auth = AuthConfig(bearer_token="global-token")
        cfg = _config_with_auth(["http://app.example.com"], global_auth)
        orc = ScanOrchestrator(config=cfg, tools=[_AuthCapturingTool()])
        orc.run()
        received = _AuthCapturingTool.captured_auth.get("http://app.example.com")
        assert received is not None
        assert received.bearer_token == "global-token"

    def test_per_target_override_replaces_global(self):
        override = AuthConfig(bearer_token="target-token")
        global_auth = AuthConfig(
            bearer_token="global-token",
            targets={"http://app.example.com": override},
        )
        cfg = _config_with_auth(["http://app.example.com"], global_auth)
        orc = ScanOrchestrator(config=cfg, tools=[_AuthCapturingTool()])
        orc.run()
        received = _AuthCapturingTool.captured_auth.get("http://app.example.com")
        assert received is not None
        assert received.bearer_token == "target-token"

    def test_each_target_gets_its_own_auth(self):
        global_auth = AuthConfig(
            bearer_token="global-token",
            targets={
                "http://app.example.com": AuthConfig(bearer_token="app-token"),
                "http://admin.example.com": AuthConfig(bearer_token="admin-token"),
            },
        )
        targets = ["http://app.example.com", "http://admin.example.com"]
        cfg = _config_with_auth(targets, global_auth)
        orc = ScanOrchestrator(config=cfg, tools=[_AuthCapturingTool()])
        orc.run()
        assert _AuthCapturingTool.captured_auth["http://app.example.com"].bearer_token == "app-token"
        assert _AuthCapturingTool.captured_auth["http://admin.example.com"].bearer_token == "admin-token"
