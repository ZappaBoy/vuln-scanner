"""Tests for AbstractTool.exec() — custom-argv raw execution primitive (M0).

Uses only host-safe shell utilities (echo/sleep/printf); never a real scanner.
"""

from vuln_scanner.tools.abstract import _EXEC_TRUNCATE, AbstractTool
from vuln_scanner.tools.enums import ScanMode
from vuln_scanner.tools.models import ExecResult, Finding, ScanInput


class _EchoTool(AbstractTool):
    name: str = "echo_tool"
    binary: str = "echo"
    category: str = "test"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["echo", "hello"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []


class _SleepTool(AbstractTool):
    name: str = "sleep_tool"
    binary: str = "sleep"
    category: str = "test"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["sleep", "0"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []


class _MissingTool(AbstractTool):
    name: str = "missing_tool"
    binary: str = "definitely_not_a_real_binary_xyz"
    category: str = "test"

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return [self.binary]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []


class TestExec:
    def test_returns_exec_result(self):
        r = _EchoTool().exec(["hello", "world"], timeout=10)
        assert isinstance(r, ExecResult)
        assert r.tool == "echo_tool"
        assert r.binary == "echo"

    def test_argv_assembled_after_binary(self):
        r = _EchoTool().exec(["-n", "custom-arg"], timeout=10)
        assert r.argv == ["-n", "custom-arg"]
        # echo -n custom-arg → no trailing newline
        assert r.stdout == "custom-arg"

    def test_stdout_captured(self):
        r = _EchoTool().exec(["chained-output"], timeout=10)
        assert "chained-output" in r.stdout
        assert r.exit_code == 0
        assert r.ok is True

    def test_falls_back_to_name_when_no_binary(self):
        class _NoBinary(_EchoTool):
            binary: str = ""

        r = _NoBinary().exec(["x"], timeout=10)
        # binary empty → uses name "echo_tool" which does not exist
        assert r.binary == "echo_tool"
        assert r.error.startswith("Binary not found")

    def test_missing_binary_sets_error(self):
        r = _MissingTool().exec(["--version"], timeout=10)
        assert r.exit_code is None
        assert "Binary not found" in r.error
        assert r.ok is False

    def test_timeout_sets_timed_out(self):
        class _Sleep5(_SleepTool):
            def build_command(self, target, scan_input):
                return ["sleep", "5"]

        r = _Sleep5().exec(["5"], timeout=1)
        assert r.timed_out is True
        assert r.ok is False
        assert "Timed out" in r.error

    def test_nonzero_exit_not_ok_but_no_error(self):
        # `sh -c 'exit 3'` → exit code 3, no launch error
        class _Sh(AbstractTool):
            name: str = "sh_tool"
            binary: str = "sh"
            category: str = "test"

            def build_command(self, target, scan_input):
                return ["sh"]

            def parse_output(self, raw, target):
                return []

        r = _Sh().exec(["-c", "exit 3"], timeout=10)
        assert r.exit_code == 3
        assert r.error == ""
        assert r.ok is False

    def test_stdout_truncated(self):
        # Emit more than _EXEC_TRUNCATE chars via printf
        class _Printf(AbstractTool):
            name: str = "printf_tool"
            binary: str = "sh"
            category: str = "test"

            def build_command(self, target, scan_input):
                return ["sh"]

            def parse_output(self, raw, target):
                return []

        big = _EXEC_TRUNCATE + 5000
        r = _Printf().exec(["-c", f"head -c {big} /dev/zero | tr '\\0' 'a'"], timeout=10)
        assert len(r.stdout) == _EXEC_TRUNCATE

    def test_exec_does_not_parse_findings(self):
        # exec never returns Findings — that's ScanResult's job
        r = _EchoTool().exec(["hello"], timeout=10)
        assert not hasattr(r, "findings")


def _scan_input() -> ScanInput:
    return ScanInput(targets=["http://example.com"], timeout=10, mode=ScanMode.ACTIVE)
