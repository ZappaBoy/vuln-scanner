import json
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool


class RESTlerTool(AbstractTool):
    name: str = "restler"
    binary: str = "restler-fuzzer"
    category: str = "api"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # placeholder — multi-phase execution handled in run()
        return []

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
            if "500" in str(status) or "InternalServerError" in bug_type:
                sev = Severity.HIGH
            elif "Auth" in bug_type or "Unauthorized" in bug_type:
                sev = Severity.CRITICAL

            findings.append(Finding(
                title=f"RESTler: {bug_type or 'Bug'} — {method} {endpoint}",
                severity=sev,
                description=(
                    f"RESTler found '{bug_type}' on {method} {endpoint} "
                    f"(HTTP {status})"
                    + (f". Replay: {replay}" if replay else "")
                ),
                tool=self.name,
                target=target,
                raw=item,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        import os as _os

        # Determine spec file and server URL
        if _os.path.isfile(target):
            spec_file = target
            server_url = None
        else:
            server_url = target if target.startswith("http") else f"https://{target}"
            spec_file = None

        workdir = tempfile.mkdtemp(prefix="vs_restler_")
        start = time.monotonic()

        try:
            compile_cmd = ["restler-fuzzer", "compile", "--api_spec", spec_file or "swagger.json"]
            if spec_file is None:
                # Try to fetch spec from common endpoints
                for path in ("/swagger.json", "/openapi.json", "/api-docs"):
                    spec_url = server_url.rstrip("/") + path
                    try:
                        import urllib.request
                        urllib.request.urlretrieve(spec_url, _os.path.join(workdir, "spec.json"))
                        spec_file = _os.path.join(workdir, "spec.json")
                        break
                    except Exception:
                        continue

                if spec_file is None:
                    return ScanResult(
                        tool=self.name, target=target, status=ScanStatus.SKIPPED,
                    )
                compile_cmd = ["restler", "compile", "--api_spec", spec_file]

            proc = subprocess.run(
                compile_cmd, capture_output=True, text=True,
                cwd=workdir, timeout=120,
            )
            if proc.returncode != 0:
                return ScanResult(
                    tool=self.name, target=target, status=ScanStatus.FAILED,
                    error=f"RESTler compile failed: {proc.stderr[:300]}",
                )

            grammar = _os.path.join(workdir, "Compile", "grammar.py")
            dictionary = _os.path.join(workdir, "Compile", "dict.json")

            fuzzing_mode_map = {
                ScanMode.PASSIVE: ("bfs-minimal", "0.1"),
                ScanMode.ACTIVE: ("bfs", "0.5"),
                ScanMode.AGGRESSIVE: ("bfs-fast", "1"),
                ScanMode.PARANOID: ("bfs-fast", "2"),
            }
            fuzzing_mode, time_budget = fuzzing_mode_map.get(
                scan_input.mode, ("bfs", "0.5")
            )

            fuzz_cmd = [
                "restler-fuzzer",
                "--restler_grammar", grammar,
                "--custom_mutations", dictionary,
                "--fuzzing_mode", fuzzing_mode,
                "--time_budget", time_budget,
                "--save_results_in_fixed_dirname", "True",
            ]
            if server_url:
                from urllib.parse import urlparse
                parsed = urlparse(server_url)
                host = parsed.hostname or target
                port = parsed.port or (80 if server_url.startswith("http://") else 443)
                fuzz_cmd += ["--target_ip", host, "--target_port", str(port)]
                if server_url.startswith("http://"):
                    fuzz_cmd.append("--no_ssl")

            fuzz_cmd += scan_input.extra_args

            proc2 = subprocess.run(
                fuzz_cmd, capture_output=True, text=True,
                cwd=workdir, timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start

            # Parse bug bucket JSON files — search recursively since the output
            # directory name depends on the fuzzing mode and run timestamp.
            import glob
            raw_findings = ""
            for fpath in glob.glob(
                _os.path.join(workdir, "**", "BugBuckets", "*.json"),
                recursive=True,
            ):
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    raw_findings += f.read() + "\n"

            findings = self.parse_output(raw_findings, target)
            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=duration, status=ScanStatus.SUCCESS,
                raw_output=proc2.stdout + proc2.stderr,
            )

        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout),
                              status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target,
                              status=ScanStatus.FAILED,
                              error="restler / restler-fuzzer not found — image may need rebuilding")
        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
