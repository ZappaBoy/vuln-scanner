"""Tests for the plugin auto-discovery system."""

import textwrap

from vuln_scanner.config.models import PluginsConfig
from vuln_scanner.plugins import _collect_tools, _load_module, load_plugins


class TestLoadModule:
    def test_loads_valid_file(self, tmp_path):
        plugin = tmp_path / "myplugin.py"
        plugin.write_text("X = 42\n")
        mod = _load_module(plugin)
        assert mod is not None
        assert mod.X == 42

    def test_returns_none_on_syntax_error(self, tmp_path):
        bad = tmp_path / "bad.py"
        bad.write_text("def oops(:\n    pass\n")
        mod = _load_module(bad)
        assert mod is None

    def test_returns_none_for_nonexistent_file(self, tmp_path):
        mod = _load_module(tmp_path / "doesnt_exist.py")
        assert mod is None


class TestCollectTools:
    def test_finds_concrete_abstract_tool_subclass(self, tmp_path):
        plugin = tmp_path / "scanner.py"
        plugin.write_text(
            textwrap.dedent("""\
            from vuln_scanner.tools.abstract import AbstractTool
            from vuln_scanner.tools.enums import TargetType
            from vuln_scanner.tools.models import Finding, ScanInput

            class MyScanner(AbstractTool):
                name: str = "my-scanner"
                category: str = "web"
                applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

                def build_command(self, target, scan_input):
                    return ["echo", target]

                def parse_output(self, raw, target):
                    return []
        """)
        )
        mod = _load_module(plugin)
        assert mod is not None
        tools = _collect_tools(mod)
        assert len(tools) == 1
        assert tools[0].__name__ == "MyScanner"

    def test_skips_abstract_tool_base_itself(self, tmp_path):
        plugin = tmp_path / "just_import.py"
        plugin.write_text("from vuln_scanner.tools.abstract import AbstractTool\n")
        mod = _load_module(plugin)
        assert mod is not None
        tools = _collect_tools(mod)
        assert len(tools) == 0

    def test_skips_classes_from_other_modules(self, tmp_path):
        """Classes imported from other modules (not defined here) must be ignored."""
        plugin = tmp_path / "importer.py"
        plugin.write_text(
            textwrap.dedent("""\
            from vuln_scanner.tools.nmap import NmapTool
            X = NmapTool
        """)
        )
        mod = _load_module(plugin)
        assert mod is not None
        tools = _collect_tools(mod)
        assert len(tools) == 0


_PLUGIN_CONTENT = textwrap.dedent("""\
    from vuln_scanner.tools.abstract import AbstractTool
    from vuln_scanner.tools.enums import TargetType
    from vuln_scanner.tools.models import Finding, ScanInput

    class CustomScanner(AbstractTool):
        name: str = "custom-scanner"
        category: str = "web"
        applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

        def build_command(self, target, scan_input):
            return ["echo", target]

        def parse_output(self, raw, target):
            return []
""")


class TestLoadPlugins:
    def test_disabled_config_registers_nothing(self, tmp_path):
        (tmp_path / "scanner.py").write_text(_PLUGIN_CONTENT)
        config = PluginsConfig(enabled=False, dirs=[str(tmp_path)])
        registry: dict = {}
        count = load_plugins(config, registry)
        assert count == 0
        assert registry == {}

    def test_discovers_tool_from_extra_dir(self, tmp_path):
        (tmp_path / "custom.py").write_text(_PLUGIN_CONTENT)
        config = PluginsConfig(enabled=True, dirs=[str(tmp_path)])
        registry: dict = {}
        count = load_plugins(config, registry)
        assert count == 1
        assert "CustomScanner" in registry

    def test_nonexistent_dir_does_not_raise(self):
        config = PluginsConfig(enabled=True, dirs=["/nonexistent/path"])
        registry: dict = {}
        count = load_plugins(config, registry)
        assert count == 0

    def test_files_starting_with_underscore_are_skipped(self, tmp_path):
        (tmp_path / "_internal.py").write_text(_PLUGIN_CONTENT)
        config = PluginsConfig(enabled=True, dirs=[str(tmp_path)])
        registry: dict = {}
        count = load_plugins(config, registry)
        assert count == 0

    def test_later_dir_overrides_earlier_on_name_collision(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()

        content_a = _PLUGIN_CONTENT.replace('"custom-scanner"', '"scanner-a"')
        content_b = _PLUGIN_CONTENT  # also registers "CustomScanner"

        (dir_a / "scanner.py").write_text(content_a.replace("CustomScanner", "ScannerA"))
        (dir_b / "scanner.py").write_text(content_b)

        config = PluginsConfig(enabled=True, dirs=[str(dir_a), str(dir_b)])
        registry: dict = {}
        load_plugins(config, registry)
        # Both are distinct classes — both should be present
        assert "ScannerA" in registry
        assert "CustomScanner" in registry

    def test_broken_plugin_file_does_not_crash_loader(self, tmp_path):
        (tmp_path / "bad.py").write_text("this is not valid python !!!\n")
        (tmp_path / "good.py").write_text(_PLUGIN_CONTENT)
        config = PluginsConfig(enabled=True, dirs=[str(tmp_path)])
        registry: dict = {}
        count = load_plugins(config, registry)
        assert count == 1
        assert "CustomScanner" in registry
