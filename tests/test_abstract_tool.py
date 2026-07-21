"""Tests for AbstractTool verbose/silent flag mechanism."""
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_scanner.tools.abstract import AbstractTool, _log_tool_output
from vuln_scanner.tools.models import ScanInput, ScanResult
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity
from vuln_scanner.tools.models import Finding


class _EchoTool(AbstractTool):
    """Minimal tool for testing: echoes a fixed string."""
    name: str = "echo_tool"
    category: str = "test"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", "hello"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []


class _SilentEchoTool(AbstractTool):
    name: str = "silent_echo"
    category: str = "test"
    silent_flags: list[str] = ["--quiet"]
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", "--quiet", "hello"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []


def _scan_input() -> ScanInput:
    return ScanInput(targets=["http://example.com"], timeout=10, mode=ScanMode.ACTIVE)


class TestVerboseFlags:
    def test_default_empty(self):
        t = _EchoTool()
        assert t.verbose_flags == []
        assert t.silent_flags == []

    def test_silent_flags_stripped_in_debug(self):
        tool = _SilentEchoTool()
        inp = _scan_input()
        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = ""
            m.stderr = ""
            m.returncode = 0
            return m

        with patch("subprocess.run", side_effect=fake_run):
            with patch.object(logging.Logger, "isEnabledFor", return_value=True):
                tool.run("http://example.com", inp)

        assert captured_cmds, "subprocess.run was not called"
        cmd = captured_cmds[0]
        assert "--quiet" not in cmd
        assert "-v" in cmd

    def test_flags_not_applied_in_info_mode(self):
        tool = _SilentEchoTool()
        inp = _scan_input()
        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = ""
            m.stderr = ""
            m.returncode = 0
            return m

        with patch("subprocess.run", side_effect=fake_run):
            with patch.object(logging.Logger, "isEnabledFor", return_value=False):
                tool.run("http://example.com", inp)

        cmd = captured_cmds[0]
        assert "--quiet" in cmd
        assert "-v" not in cmd

    def test_nuclei_silent_flag_declared(self):
        from vuln_scanner.tools.nuclei import NucleiTool
        t = NucleiTool()
        assert "-silent" in t.silent_flags
        assert "-v" in t.verbose_flags

    def test_nmap_verbose_flag_declared(self):
        from vuln_scanner.tools.nmap import NmapTool
        t = NmapTool()
        assert "-v" in t.verbose_flags

    def test_bandit_silent_flag_declared(self):
        from vuln_scanner.tools.bandit import BanditTool
        t = BanditTool()
        assert "-q" in t.silent_flags

    def test_semgrep_flags_declared(self):
        from vuln_scanner.tools.semgrep import SemgrepTool
        t = SemgrepTool()
        assert "--quiet" in t.silent_flags
        assert "-v" in t.verbose_flags

    def test_trivy_flags_declared(self):
        from vuln_scanner.tools.trivy import TrivyTool
        t = TrivyTool()
        assert "--quiet" in t.silent_flags
        assert "--debug" in t.verbose_flags


class TestLogToolOutput:
    def test_empty_output_skipped(self, caplog):
        logger = logging.getLogger("test")
        with caplog.at_level(logging.DEBUG, logger="test"):
            _log_tool_output(logger, "tool", "", "")
        assert not caplog.records

    def test_stdout_logged(self, caplog):
        logger = logging.getLogger("test")
        with caplog.at_level(logging.DEBUG, logger="test"):
            _log_tool_output(logger, "mytool", "output line", "")
        assert any("stdout" in r.message for r in caplog.records)
        assert any("output line" in r.message for r in caplog.records)

    def test_stderr_logged(self, caplog):
        logger = logging.getLogger("test")
        with caplog.at_level(logging.DEBUG, logger="test"):
            _log_tool_output(logger, "mytool", "", "error text")
        assert any("stderr" in r.message for r in caplog.records)

    def test_long_output_truncated(self, caplog):
        logger = logging.getLogger("test")
        big = "x" * 20000
        with caplog.at_level(logging.DEBUG, logger="test"):
            _log_tool_output(logger, "mytool", big, "")
        combined = " ".join(r.message for r in caplog.records)
        assert "truncated" in combined


class TestDirsearchDebugSafety:
    def test_no_color_not_in_silent_flags(self):
        from vuln_scanner.tools.dirsearch import DirsearchTool
        t = DirsearchTool()
        assert "--no-color" not in t.silent_flags

    def test_quiet_in_silent_flags(self):
        from vuln_scanner.tools.dirsearch import DirsearchTool
        t = DirsearchTool()
        assert "--quiet" in t.silent_flags

    def test_no_color_stays_in_debug_cmd(self):
        from vuln_scanner.tools.dirsearch import DirsearchTool
        t = DirsearchTool()
        inp = _scan_input()
        cmd = t.build_command("http://example.com", inp)
        # Simulate debug mode flag manipulation
        cmd_debug = [a for a in cmd if a not in t.silent_flags] + t.verbose_flags
        assert "--no-color" in cmd_debug
        assert "--quiet" not in cmd_debug

    def test_parse_output_unaffected_by_debug_mode(self):
        from vuln_scanner.tools.dirsearch import DirsearchTool
        t = DirsearchTool()
        # Simulate dirsearch output when --quiet is stripped: includes progress lines
        raw = (
            "Extensions: php, html | HTTP method: GET | Threads: 20\n"  # progress line
            "Target: http://example.com/\n"
            "200    1KB   http://example.com/admin\n"
            "403    512B  http://example.com/.htaccess\n"
            "[####################] 100%\n"  # progress bar line
        )
        findings = t.parse_output(raw, "http://example.com")
        # Should find the 200 and 403 entries, ignore progress lines
        urls = [f.raw["url"] for f in findings]
        assert "http://example.com/admin" in urls
        assert "http://example.com/.htaccess" in urls
        # Progress lines must not create findings
        assert not any("##" in u or "Extensions" in u for u in urls)
