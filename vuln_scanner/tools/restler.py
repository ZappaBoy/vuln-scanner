import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import urlopen

from vuln_scanner.assets import AssetType
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SPEC_PATHS = ("/swagger.json", "/openapi.json", "/api-docs")
_SPEC_FETCH_TIMEOUT = 4  # seconds per URL attempt


def _fetch_spec(server_url: str, dest: str) -> bool:
    """Try to download an OpenAPI spec from common paths. Returns True on success."""
    base = server_url.rstrip("/")
    for path in _SPEC_PATHS:
        try:
            with urlopen(base + path, timeout=_SPEC_FETCH_TIMEOUT) as resp:
                with open(dest, "wb") as f:
                    f.write(resp.read())
            return True
        except Exception:
            continue
    return False


def _run_proc(cmd: list[str], cwd: str, timeout: int) -> subprocess.CompletedProcess:
    """Run cmd in its own process group; SIGKILL the whole group on timeout."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            proc.kill()
        proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


class RESTlerTool(AbstractTool):
    name: str = "restler"
    binary: str = "restler-fuzzer"
    category: str = "api"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})
    consumes: frozenset[AssetType] = frozenset({AssetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # multi-phase; run() builds all commands

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            bug_type = item.get("bucketName", item.get("bugType", ""))
            request = item.get("request", {})
            endpoint = request.get("endpoint", item.get("endpoint", ""))
            method = request.get("method", item.get("method", ""))
            status = item.get("statusCode", item.get("status_code", 0))
            replay = item.get("replayFile", "")
            if not bug_type and not endpoint:
                continue
            sev = Severity.HIGH
            if "Auth" in bug_type or "Unauthorized" in bug_type:
                sev = Severity.CRITICAL
            findings.append(
                Finding(
                    title=f"RESTler: {bug_type or 'Bug'} — {method} {endpoint}",
                    severity=sev,
                    description=(
                        f"RESTler found '{bug_type}' on {method} {endpoint} "
                        f"(HTTP {status})" + (f". Replay: {replay}" if replay else "")
                    ),
                    tool=self.name,
                    target=target,
                    raw=item,
                )
            )
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        if os.path.isfile(target):
            spec_file = target
            server_url = None
        else:
            server_url = target if target.startswith("http") else f"https://{target}"
            spec_file = None

        workdir = tempfile.mkdtemp(prefix="vs_restler_")
        start = time.monotonic()
        try:
            if spec_file is None:
                dest = os.path.join(workdir, "spec.json")
                if not _fetch_spec(server_url, dest):
                    return ScanResult(
                        tool=self.name, target=target, status=ScanStatus.SKIPPED,
                        error="No OpenAPI spec found at common endpoints",
                    )
                spec_file = dest

            compile_cmd = [self.binary, "compile", "--api_spec", spec_file]
            try:
                proc = _run_proc(compile_cmd, workdir, timeout=120)
            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout),
                    status=ScanStatus.TIMEOUT,
                    error="RESTler compile timed out",
                )
            if proc.returncode != 0:
                return ScanResult(
                    tool=self.name, target=target, status=ScanStatus.FAILED,
                    error=f"RESTler compile failed: {proc.stderr[:300]}",
                )

            grammar = os.path.join(workdir, "Compile", "grammar.py")
            dictionary = os.path.join(workdir, "Compile", "dict.json")

            fuzzing_mode_map = {
                ScanMode.PASSIVE: ("bfs-minimal", "0.1"),
                ScanMode.ACTIVE: ("bfs", "0.5"),
                ScanMode.AGGRESSIVE: ("bfs-fast", "1"),
                ScanMode.PARANOID: ("bfs-fast", "2"),
            }
            fuzzing_mode, time_budget = fuzzing_mode_map.get(scan_input.mode, ("bfs", "0.5"))

            fuzz_cmd = [
                self.binary,
                "--restler_grammar", grammar,
                "--custom_mutations", dictionary,
                "--fuzzing_mode", fuzzing_mode,
                "--time_budget", time_budget,
                "--save_results_in_fixed_dirname", "True",
            ]
            if server_url:
                parsed = urlparse(server_url)
                host = parsed.hostname or target
                port = parsed.port or (80 if server_url.startswith("http://") else 443)
                fuzz_cmd += ["--target_ip", host, "--target_port", str(port)]
                if server_url.startswith("http://"):
                    fuzz_cmd.append("--no_ssl")
            fuzz_cmd += scan_input.extra_args

            try:
                proc2 = _run_proc(fuzz_cmd, workdir, timeout=scan_input.timeout)
            except subprocess.TimeoutExpired:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=float(scan_input.timeout),
                    status=ScanStatus.TIMEOUT,
                    error=f"RESTler timed out after {scan_input.timeout}s",
                )
            duration = time.monotonic() - start

            import glob
            raw_findings = ""
            for fpath in glob.glob(
                os.path.join(workdir, "**", "BugBuckets", "*.json"), recursive=True
            ):
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    raw_findings += f.read() + "\n"

            findings = self.parse_output(raw_findings, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=proc2.stdout + proc2.stderr,
            )

        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, status=ScanStatus.FAILED,
                error=f"Binary not found: {self.binary}",
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
