"""Container-only PoC runner — REFUSES to execute outside the Docker image.

The `VS_IN_CONTAINER` environment variable must be set to "1" (baked into
the Dockerfile via `ENV VS_IN_CONTAINER=1`) for any execution to proceed.
This is a hard safety guard to ensure PoCs never run on the developer's host.
"""

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from vuln_scanner.poc.models import Poc, PocVerdict

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig
    from vuln_scanner.model import Assessment

log = logging.getLogger(__name__)

_CONTAINER_MARKER = "VS_IN_CONTAINER"
_EXTENSIONS = {"python": ".py", "bash": ".sh"}
_RUNNERS = {"python": ["python3"], "bash": ["bash"]}


def _is_in_container() -> bool:
    return os.environ.get(_CONTAINER_MARKER, "").strip() == "1"


class PocRunner:
    def __init__(self, config: "LLMConfig") -> None:
        self._config = config

    def run_all(
        self,
        pocs: list[Poc],
        assessment: "Assessment",
    ) -> list[Poc]:
        """Execute eligible PoCs and attach evidence to findings.

        Silently returns unmodified pocs when not inside the container.
        """
        features = self._config.features
        if not features.execute_poc:
            log.debug("PoC execution disabled (execute_poc=false).")
            return pocs

        if not _is_in_container():
            log.warning(
                "PoC execution refused: '%s' env var is not '1'. "
                "PoC execution is only allowed inside the Docker container.",
                _CONTAINER_MARKER,
            )
            return pocs

        executed = 0
        for poc in pocs:
            if not poc.safe_to_run:
                poc.verdict = PocVerdict.UNSAFE
                log.debug("PoC %s skipped: marked unsafe (%s).", poc.id, poc.safety_notes)
                continue

            try:
                self._run_one(poc, assessment)
                executed += 1
            except Exception as exc:
                log.warning("PoC %s execution error: %s", poc.id, exc)
                poc.verdict = PocVerdict.FAILED
                poc.stderr = str(exc)

        log.info("PoC runner: executed %d/%d script(s).", executed, len(pocs))
        return pocs

    def _run_one(self, poc: Poc, assessment: "Assessment") -> None:
        poc_cfg = self._config.poc
        lang = poc.language.lower()
        runner_cmd = _RUNNERS.get(lang, ["bash"])
        ext = _EXTENSIONS.get(lang, ".sh")

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=ext,
            prefix=f"vs_poc_{poc.id}_",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(poc.script)
            tmp_path = f.name

        try:
            Path(tmp_path).chmod(0o700)
            log.debug("Running PoC %s: %s %s", poc.id, runner_cmd[0], tmp_path)
            proc = subprocess.run(
                runner_cmd + [tmp_path],
                capture_output=True,
                text=True,
                timeout=poc_cfg.timeout,
            )
            poc.exit_code = proc.returncode
            poc.stdout = proc.stdout[:4000]
            poc.stderr = proc.stderr[:2000]

            indicator = poc.expected_indicator or ""
            combined = poc.stdout + poc.stderr
            if indicator and indicator.lower() in combined.lower():
                poc.verdict = PocVerdict.CONFIRMED
            elif proc.returncode == 0:
                poc.verdict = PocVerdict.INCONCLUSIVE
            else:
                poc.verdict = PocVerdict.FAILED

            # Attach evidence back to findings via raw dict
            evidence = (
                f"PoC {poc.id} ({lang}) — verdict: {poc.verdict.value}\n"
                f"Exit code: {poc.exit_code}\n"
                f"--- stdout ---\n{poc.stdout}\n"
                f"--- stderr ---\n{poc.stderr}"
            )
            for r in assessment.results:
                for finding in r.findings:
                    fkey = f"{finding.tool}::{finding.target}::{finding.title}"
                    if fkey in poc.finding_keys:
                        finding.raw["_poc_evidence"] = evidence

        except subprocess.TimeoutExpired:
            poc.verdict = PocVerdict.FAILED
            poc.stderr = f"Timed out after {poc_cfg.timeout}s"
            log.warning("PoC %s timed out.", poc.id)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
