"""Tests for the wave/fixpoint tool-chaining engine (mocked — no real subprocesses)."""

from vuln_scanner.assets import Asset, AssetStore, AssetType
from vuln_scanner.config.models import AppConfig, ChainingConfig, ScanConfig
from vuln_scanner.orchestrator import ScanOrchestrator
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_INFO = Severity.INFO


# ── Minimal mock tools for chaining tests ─────────────────────────────────────


class _SubdomainProducer(AbstractTool):
    """Wave-0 tool: runs on HOSTs, emits SUBDOMAIN assets."""

    name: str = "mock_subdomain"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
    produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})
    _subdomains: list[str] = []

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        findings = [
            Finding(
                title=f"Subdomain: {sd}",
                severity=_INFO,
                description=f"Found {sd}",
                tool=self.name,
                target=target,
                raw={"host": sd},
            )
            for sd in self._subdomains
        ]
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS, findings=findings)

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.SUBDOMAIN, value=f.raw["host"], source=self.name, target=result.target)
            for f in result.findings
        ]


class _ParamProducer(AbstractTool):
    """Chained tool: consumes URL, emits PARAM assets."""

    name: str = "mock_param"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    produces: frozenset[AssetType] = frozenset({AssetType.PARAM})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})
    calls: list[str] = []

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _ParamProducer.calls.append(target)
        findings = [
            Finding(
                title=f"Param: id on {target}",
                severity=_INFO,
                description=f"Parameter id found on {target}",
                tool=self.name,
                target=target,
                raw={"url": target, "method": "GET", "params": ["id"]},
            )
        ]
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS, findings=findings)

    def extract_assets(self, result: ScanResult) -> list[Asset]:
        return [
            Asset(type=AssetType.PARAM, value=f"{result.target}?id", source=self.name, target=result.target)
            for f in result.findings
        ]


class _InjectionConsumer(AbstractTool):
    """Terminal consumer: consumes PARAM, produces nothing."""

    name: str = "mock_inject"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.PARAM})
    calls: list[str] = []

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        _InjectionConsumer.calls.append(target)
        return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _chaining_config(targets: list[str], mode: ScanMode = ScanMode.ACTIVE) -> AppConfig:
    cfg = AppConfig()
    cfg.scan = ScanConfig(targets=targets, max_concurrent=2, mode=mode)
    cfg.chaining = ChainingConfig(enabled=True, max_depth=5, max_new_targets=100)
    return cfg


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestAssetStore:
    def test_add_deduplicates_by_type_value(self):
        store = AssetStore()
        a1 = Asset(type=AssetType.SUBDOMAIN, value="sub.example.com", source="t1", target="example.com")
        a2 = Asset(type=AssetType.SUBDOMAIN, value="sub.example.com", source="t2", target="example.com")
        assert store.add(a1) is True
        assert store.add(a2) is False  # duplicate
        assert len(store.get(AssetType.SUBDOMAIN)) == 1

    def test_add_different_types_both_stored(self):
        store = AssetStore()
        store.add(Asset(type=AssetType.SUBDOMAIN, value="x", source="t", target="t"))
        store.add(Asset(type=AssetType.URL, value="x", source="t", target="t"))
        assert len(store.get(AssetType.SUBDOMAIN)) == 1
        assert len(store.get(AssetType.URL)) == 1

    def test_seed_from_targets(self):
        store = AssetStore()
        store.seed_from_targets(["example.com", "192.168.1.1"])
        # HOST target → no direct asset type (not URL/IP explicitly)
        # Just verify it doesn't raise

    def test_has_any(self):
        store = AssetStore()
        assert store.has_any(AssetType.SUBDOMAIN) is False
        store.add(Asset(type=AssetType.SUBDOMAIN, value="a", source="x", target="t"))
        assert store.has_any(AssetType.SUBDOMAIN) is True

    def test_get_values(self):
        store = AssetStore()
        store.add(Asset(type=AssetType.URL, value="https://a.com", source="x", target="t"))
        store.add(Asset(type=AssetType.URL, value="https://b.com", source="x", target="t"))
        vals = store.get_values(AssetType.URL)
        assert set(vals) == {"https://a.com", "https://b.com"}

    def test_total(self):
        store = AssetStore()
        store.add(Asset(type=AssetType.SUBDOMAIN, value="x", source="t", target="t"))
        store.add(Asset(type=AssetType.URL, value="y", source="t", target="t"))
        assert store.total == 2


class TestChainingWaves:
    def test_wave0_only_consumes_empty_tools(self):
        """Only tools with consumes=∅ run in Wave 0."""
        producer = _SubdomainProducer()
        producer._subdomains = ["api.target.com"]
        consumer = _ParamProducer()
        _ParamProducer.calls = []

        cfg = _chaining_config(["target.com"])
        orch = ScanOrchestrator(config=cfg, tools=[producer, consumer])
        results = orch.run()

        # ParamProducer consumes URL; no URL was seeded and producer gives SUBDOMAIN
        # so ParamProducer should NOT have run yet (no URLs in store)
        assert all(r.tool != "mock_param" for r in results)

    def test_chained_tool_runs_on_discovered_asset(self):
        """URL discovered by a Wave-0 tool unlocks ParamProducer in Wave 1."""

        class _LiveHostProducer(AbstractTool):
            name: str = "mock_live"
            category: str = "web"
            applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
            produces: frozenset[AssetType] = frozenset({AssetType.URL})

            def build_command(self, t, si):
                return []

            def parse_output(self, r, t):
                return []

            def run(self, target, scan_input):
                findings = [
                    Finding(
                        title="URL found",
                        severity=_INFO,
                        description=f"Live: {target}",
                        tool=self.name,
                        target=target,
                        raw={"url": f"https://{target}"},
                    )
                ]
                return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS, findings=findings)

            def extract_assets(self, result):
                return [
                    Asset(type=AssetType.URL, value=f.raw["url"], source=self.name, target=result.target)
                    for f in result.findings
                ]

        _ParamProducer.calls = []
        live = _LiveHostProducer()
        param = _ParamProducer()

        cfg = _chaining_config(["target.com"])
        orch = ScanOrchestrator(config=cfg, tools=[live, param])
        orch.run()

        # ParamProducer should have been called on the discovered URL
        assert len(_ParamProducer.calls) == 1
        assert _ParamProducer.calls[0] == "https://target.com"

    def test_fixpoint_no_infinite_loop(self):
        """Run reaches fixpoint when no new assets are produced."""
        _InjectionConsumer.calls = []

        class _UrlProducer(AbstractTool):
            name: str = "mock_urlprod"
            category: str = "web"
            applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
            produces: frozenset[AssetType] = frozenset({AssetType.URL})

            def build_command(self, t, si):
                return []

            def parse_output(self, r, t):
                return []

            def run(self, target, scan_input):
                findings = [
                    Finding(
                        title="URL",
                        severity=_INFO,
                        description="archived",
                        tool=self.name,
                        target=target,
                        raw={"url": "https://example.com/page"},
                    )
                ]
                return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS, findings=findings)

            def extract_assets(self, result):
                return [
                    Asset(type=AssetType.URL, value=f.raw["url"], source=self.name, target=result.target)
                    for f in result.findings
                ]

        cfg = _chaining_config(["example.com"])
        orch = ScanOrchestrator(config=cfg, tools=[_UrlProducer(), _InjectionConsumer()])
        # InjectionConsumer consumes PARAM, not URL, so it should never run
        results = orch.run()
        assert all(r.tool != "mock_inject" for r in results)

    def test_same_tool_target_not_run_twice(self):
        """The done-set prevents re-running (tool, target) pairs."""
        run_count = [0]

        class _CountingProducer(AbstractTool):
            name: str = "mock_counting"
            category: str = "network"
            applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})
            produces: frozenset[AssetType] = frozenset({AssetType.SUBDOMAIN})

            def build_command(self, t, si):
                return []

            def parse_output(self, r, t):
                return []

            def run(self, target, scan_input):
                run_count[0] += 1
                return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS)

        cfg = _chaining_config(["example.com"])
        orch = ScanOrchestrator(config=cfg, tools=[_CountingProducer()])
        orch.run()
        assert run_count[0] == 1  # exactly once, not re-triggered

    def test_max_depth_respected(self):
        """Chaining stops at max_depth even if new assets keep appearing."""
        wave_calls = [0]

        class _InfiniteProducer(AbstractTool):
            name: str = "mock_inf"
            category: str = "web"
            applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
            produces: frozenset[AssetType] = frozenset({AssetType.URL})
            consumes: frozenset[AssetType] = frozenset({AssetType.URL})
            _counter: int = 0

            def build_command(self, t, si):
                return []

            def parse_output(self, r, t):
                return []

            def run(self, target, scan_input):
                wave_calls[0] += 1
                _InfiniteProducer._counter += 1
                new_url = f"https://example.com/page{_InfiniteProducer._counter}"
                findings = [
                    Finding(
                        title="URL",
                        severity=_INFO,
                        description="url",
                        tool=self.name,
                        target=target,
                        raw={"url": new_url},
                    )
                ]
                return ScanResult(tool=self.name, target=target, status=ScanStatus.SUCCESS, findings=findings)

            def extract_assets(self, result):
                return [
                    Asset(type=AssetType.URL, value=f.raw["url"], source=self.name, target=result.target)
                    for f in result.findings
                ]

        _InfiniteProducer._counter = 0
        cfg = _chaining_config(["https://example.com"])
        cfg.chaining.max_depth = 3
        orch = ScanOrchestrator(config=cfg, tools=[_InfiniteProducer()])
        orch.run()
        # Depth 0 is Wave 0 (URL in original targets) + max_depth=3 waves
        assert wave_calls[0] <= 1 + 3


class TestChainingPassiveMode:
    def test_passive_mode_blocks_non_passive_assets(self):
        """In PASSIVE mode, PARAM assets are not propagated (not in _PASSIVE_ASSET_TYPES)."""
        from vuln_scanner.orchestrator import _PASSIVE_ASSET_TYPES

        assert AssetType.SUBDOMAIN in _PASSIVE_ASSET_TYPES
        assert AssetType.URL in _PASSIVE_ASSET_TYPES
        assert AssetType.PARAM not in _PASSIVE_ASSET_TYPES
        assert AssetType.OPEN_PORT not in _PASSIVE_ASSET_TYPES

    def test_maybe_add_asset_drops_non_passive_in_passive_mode(self):
        """_maybe_add_asset drops PARAM in PASSIVE mode."""
        store = AssetStore()
        scope = ScopeValidator(include=[], exclude=[])
        budgets: dict[str, int] = {"param": 100}
        param_asset = Asset(type=AssetType.PARAM, value="https://x.com?id=1", source="t", target="x.com")

        ScanOrchestrator._maybe_add_asset(param_asset, store, scope, ScanMode.PASSIVE, budgets)
        assert len(store.get(AssetType.PARAM)) == 0

    def test_maybe_add_asset_allows_subdomain_in_passive_mode(self):
        """_maybe_add_asset allows SUBDOMAIN in PASSIVE mode."""
        store = AssetStore()
        scope = ScopeValidator(include=[], exclude=[])
        budgets: dict[str, int] = {"subdomain": 100}
        sub_asset = Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="t", target="example.com")

        ScanOrchestrator._maybe_add_asset(sub_asset, store, scope, ScanMode.PASSIVE, budgets)
        assert len(store.get(AssetType.SUBDOMAIN)) == 1


class TestChainingBudget:
    def test_budget_exhaustion_drops_asset(self):
        """Assets beyond budget are silently dropped."""
        store = AssetStore()
        scope = ScopeValidator(include=[], exclude=[])
        budgets: dict[str, int] = {"subdomain": 2}

        for i in range(5):
            asset = Asset(type=AssetType.SUBDOMAIN, value=f"sub{i}.example.com", source="t", target="example.com")
            ScanOrchestrator._maybe_add_asset(asset, store, scope, ScanMode.ACTIVE, budgets)

        assert len(store.get(AssetType.SUBDOMAIN)) == 2


class TestChainingScope:
    def test_out_of_scope_subdomain_dropped(self):
        """Discovered subdomains outside scope are rejected before entering store."""
        store = AssetStore()
        scope = ScopeValidator(include=["*.example.com", "example.com"], exclude=[])
        budgets: dict[str, int] = {"subdomain": 100}

        in_scope = Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="t", target="example.com")
        out_of_scope = Asset(type=AssetType.SUBDOMAIN, value="evil.attacker.com", source="t", target="example.com")

        ScanOrchestrator._maybe_add_asset(in_scope, store, scope, ScanMode.ACTIVE, budgets)
        ScanOrchestrator._maybe_add_asset(out_of_scope, store, scope, ScanMode.ACTIVE, budgets)

        vals = store.get_values(AssetType.SUBDOMAIN)
        assert "api.example.com" in vals
        assert "evil.attacker.com" not in vals


class TestProducesConsumesDeclarations:
    """Spot-check that key tools have the expected produces/consumes declarations."""

    def test_subfinder_produces_subdomain(self):
        from vuln_scanner.tools.subfinder import SubfinderTool

        t = SubfinderTool()
        assert AssetType.SUBDOMAIN in t.produces
        assert not t.consumes

    def test_amass_produces_subdomain(self):
        from vuln_scanner.tools.amass import AmassTool

        t = AmassTool()
        assert AssetType.SUBDOMAIN in t.produces

    def test_httpx_produces_and_consumes(self):
        from vuln_scanner.tools.httpx import HttpxTool

        t = HttpxTool()
        assert AssetType.LIVE_HOST in t.produces
        assert AssetType.URL in t.produces
        assert AssetType.TECH in t.produces
        assert AssetType.SUBDOMAIN in t.consumes

    def test_nmap_produces_open_port(self):
        from vuln_scanner.tools.nmap import NmapTool

        t = NmapTool()
        assert AssetType.OPEN_PORT in t.produces

    def test_katana_produces_and_consumes(self):
        from vuln_scanner.tools.katana import KatanaTool

        t = KatanaTool()
        assert AssetType.URL in t.produces
        assert AssetType.JS_URL in t.produces
        assert AssetType.ENDPOINT in t.produces
        assert AssetType.URL in t.consumes
        assert AssetType.LIVE_HOST in t.consumes

    def test_gau_produces_and_consumes(self):
        from vuln_scanner.tools.gau import GauTool

        t = GauTool()
        assert AssetType.URL in t.produces
        assert AssetType.URL in t.consumes
        assert AssetType.SUBDOMAIN in t.consumes

    def test_arjun_produces_param(self):
        from vuln_scanner.tools.arjun import ArjunTool

        t = ArjunTool()
        assert AssetType.PARAM in t.produces
        assert AssetType.URL in t.consumes

    def test_whatweb_produces_tech(self):
        from vuln_scanner.tools.whatweb import WhatWebTool

        t = WhatWebTool()
        assert AssetType.TECH in t.produces

    def test_sqlmap_consumes_param(self):
        from vuln_scanner.tools.sqlmap import SQLMapTool

        t = SQLMapTool()
        assert AssetType.PARAM in t.consumes

    def test_dalfox_consumes_param(self):
        from vuln_scanner.tools.dalfox import DalfoxTool

        t = DalfoxTool()
        assert AssetType.PARAM in t.consumes

    def test_nuclei_consumes_url_and_live_host(self):
        from vuln_scanner.tools.nuclei import NucleiTool

        t = NucleiTool()
        assert AssetType.URL in t.consumes
        assert AssetType.LIVE_HOST in t.consumes

    def test_nikto_consumes_url(self):
        from vuln_scanner.tools.nikto import NiktoTool

        t = NiktoTool()
        assert AssetType.URL in t.consumes


class TestExtractAssets:
    """Unit-test extract_assets() on each producer tool."""

    def test_subfinder_extract_assets(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.models import ScanResult
        from vuln_scanner.tools.subfinder import SubfinderTool

        t = SubfinderTool()
        result = ScanResult(
            tool="subfinder",
            target="example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Subdomain: api.example.com",
                    severity=_INFO,
                    description="found",
                    tool="subfinder",
                    target="example.com",
                    raw={"host": "api.example.com"},
                )
            ],
        )
        assets = t.extract_assets(result)
        assert len(assets) == 1
        assert assets[0].type == AssetType.SUBDOMAIN
        assert assets[0].value == "api.example.com"

    def test_amass_extract_assets(self):
        from vuln_scanner.tools.amass import AmassTool
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.models import ScanResult

        t = AmassTool()
        result = ScanResult(
            tool="amass",
            target="example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Subdomain: mail.example.com",
                    severity=_INFO,
                    description="found",
                    tool="amass",
                    target="example.com",
                    raw={"name": "mail.example.com"},
                )
            ],
        )
        assets = t.extract_assets(result)
        assert len(assets) == 1
        assert assets[0].value == "mail.example.com"

    def test_httpx_extract_assets(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.httpx import HttpxTool
        from vuln_scanner.tools.models import ScanResult

        t = HttpxTool()
        result = ScanResult(
            tool="httpx",
            target="api.example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="[200] https://api.example.com",
                    severity=_INFO,
                    description="live",
                    tool="httpx",
                    target="api.example.com",
                    raw={"url": "https://api.example.com", "tech": ["nginx", "jQuery"]},
                )
            ],
        )
        assets = t.extract_assets(result)
        types = [a.type for a in assets]
        assert AssetType.LIVE_HOST in types
        assert AssetType.URL in types
        assert types.count(AssetType.TECH) == 2
        tech_values = {a.value for a in assets if a.type == AssetType.TECH}
        assert tech_values == {"nginx", "jQuery"}

    def test_nmap_extract_assets(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.models import ScanResult
        from vuln_scanner.tools.nmap import NmapTool

        t = NmapTool()
        result = ScanResult(
            tool="nmap",
            target="192.168.1.1",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Open port 443/tcp — https",
                    severity=_INFO,
                    description="open",
                    tool="nmap",
                    target="192.168.1.1",
                    raw={"port": "443", "protocol": "tcp", "service": "https"},
                )
            ],
        )
        assets = t.extract_assets(result)
        assert len(assets) == 1
        assert assets[0].type == AssetType.OPEN_PORT
        assert "443" in assets[0].value
        assert assets[0].meta["service"] == "https"

    def test_arjun_extract_assets(self):
        from vuln_scanner.tools.arjun import ArjunTool
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.models import ScanResult

        t = ArjunTool()
        url = "https://example.com/search"
        result = ScanResult(
            tool="arjun",
            target=url,
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Parameters found: GET https://example.com/search",
                    severity=_INFO,
                    description="params",
                    tool="arjun",
                    target=url,
                    raw={"url": url, "method": "GET", "params": ["q", "page"]},
                )
            ],
        )
        assets = t.extract_assets(result)
        assert len(assets) == 2
        assert all(a.type == AssetType.PARAM for a in assets)
        param_values = {a.value for a in assets}
        assert "https://example.com/search?q" in param_values
        assert "https://example.com/search?page" in param_values

    def test_katana_extract_assets_classifies_js(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.katana import KatanaTool
        from vuln_scanner.tools.models import ScanResult

        t = KatanaTool()
        result = ScanResult(
            tool="katana",
            target="https://example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Endpoint: GET https://example.com/app.js",
                    severity=_INFO,
                    description="js",
                    tool="katana",
                    target="https://example.com",
                    raw={"request": {"endpoint": "https://example.com/app.js", "method": "GET"}},
                ),
                Finding(
                    title="Endpoint: POST https://example.com/api",
                    severity=_INFO,
                    description="api",
                    tool="katana",
                    target="https://example.com",
                    raw={"request": {"endpoint": "https://example.com/api", "method": "POST"}},
                ),
                Finding(
                    title="Endpoint: GET https://example.com/page",
                    severity=_INFO,
                    description="page",
                    tool="katana",
                    target="https://example.com",
                    raw={"request": {"endpoint": "https://example.com/page", "method": "GET"}},
                ),
            ],
        )
        assets = t.extract_assets(result)
        types_by_val = {a.value: a.type for a in assets}
        assert types_by_val["https://example.com/app.js"] == AssetType.JS_URL
        assert types_by_val["https://example.com/api"] == AssetType.ENDPOINT
        assert types_by_val["https://example.com/page"] == AssetType.URL

    def test_whatweb_extract_assets(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.models import ScanResult
        from vuln_scanner.tools.whatweb import WhatWebTool

        t = WhatWebTool()
        result = ScanResult(
            tool="whatweb",
            target="https://example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Technology detected: WordPress 6.4",
                    severity=_INFO,
                    description="tech",
                    tool="whatweb",
                    target="https://example.com",
                    raw={"tech": "WordPress", "version": "6.4", "details": {}},
                ),
                Finding(
                    title="Technology detected: nginx",
                    severity=_INFO,
                    description="tech",
                    tool="whatweb",
                    target="https://example.com",
                    raw={"tech": "nginx", "version": "", "details": {}},
                ),
            ],
        )
        assets = t.extract_assets(result)
        vals = {a.value for a in assets}
        assert "WordPress:6.4" in vals
        assert "nginx" in vals
        assert all(a.type == AssetType.TECH for a in assets)

    def test_gau_extract_assets(self):
        from vuln_scanner.tools.enums import ScanStatus
        from vuln_scanner.tools.gau import GauTool
        from vuln_scanner.tools.models import ScanResult

        t = GauTool()
        result = ScanResult(
            tool="gau",
            target="example.com",
            status=ScanStatus.SUCCESS,
            findings=[
                Finding(
                    title="Archived URL: https://example.com/old",
                    severity=_INFO,
                    description="archived",
                    tool="gau",
                    target="example.com",
                    raw={"url": "https://example.com/old"},
                ),
            ],
        )
        assets = t.extract_assets(result)
        assert len(assets) == 1
        assert assets[0].type == AssetType.URL
        assert assets[0].value == "https://example.com/old"
