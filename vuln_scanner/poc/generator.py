"""Host-safe PoC generator — produces scripts, never executes them."""


import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from vuln_scanner.poc.models import Poc
from vuln_scanner.tools.models import Finding

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig
    from vuln_scanner.llm.client import LLMClient
    from vuln_scanner.model import Assessment
    from vuln_scanner.tools.models import ScanResult

log = logging.getLogger(__name__)

_EXTENSIONS = {"python": ".py", "bash": ".sh"}
_SHEBANGS = {"python": "#!/usr/bin/env python3", "bash": "#!/usr/bin/env bash"}

# Hard denylist patterns — if a generated script matches any of these it is
# flagged unsafe regardless of what the LLM says.
_DENYLIST_RE = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in [
        r"rm\s+-rf\s+/",             # recursive delete from root
        r"mkfs\.",                    # format filesystem
        r"dd\s+.*of=/dev/",          # overwrite block devices
        r"fork\s*\(\s*\)",           # fork bomb foundation
        r":\(\s*\)\s*\{",            # bash fork bomb definition f(){ f|f& }
        r"while\s+true.*fork",      # loop+fork
        r"shutdown|reboot|halt|poweroff",  # system control
        r"iptables\s+-F",            # flush firewall rules
        r"/etc/passwd|/etc/shadow",  # system credential files
        r"DROP\s+TABLE|TRUNCATE\s+TABLE",  # SQL destruction
    ]
]


def _is_safe(script: str) -> tuple[bool, str]:
    for pattern in _DENYLIST_RE:
        m = pattern.search(script)
        if m:
            return False, f"Denylist match: {m.group()!r}"
    return True, ""


class PocGenerator:
    def __init__(self, config: "LLMConfig") -> None:
        self._config = config
        self._client: "LLMClient | None" = None

    def _get_client(self) -> "LLMClient":
        if self._client is None:
            from vuln_scanner.llm.client import LLMClient
            self._client = LLMClient(self._config)
        return self._client

    def _should_generate(self, finding: Finding) -> bool:
        poc_cfg = self._config.poc
        sev = finding.severity.value.lower()
        return sev in [s.lower() for s in poc_cfg.only_severities]

    def _finding_key(self, f: Finding) -> str:
        return f"{f.tool}::{f.target}::{f.title}"

    def generate(
        self,
        assessment: "Assessment",
        assets_dir: Path,
    ) -> list[Poc]:
        """Generate PoC scripts for eligible findings. Returns list of Poc objects."""
        if not self._config.is_active:
            return []

        poc_plans: dict[str, str] = assessment.metadata.get("llm_poc_plans", {})
        poc_cfg = self._config.poc
        assets_dir.mkdir(parents=True, exist_ok=True)

        pocs: list[Poc] = []
        count = 0

        for r in assessment.results:
            features = self._config.resolve_features(r.tool, self._get_category(r))
            if not features.generate_poc:
                continue

            for finding in r.findings:
                if finding.false_positive:
                    continue
                if not self._should_generate(finding):
                    continue
                if count >= poc_cfg.max_pocs:
                    log.debug("PoC limit (%d) reached.", poc_cfg.max_pocs)
                    break

                fkey = self._finding_key(finding)
                poc_plan = poc_plans.get(fkey, "")

                try:
                    poc = self._generate_one(finding, poc_plan, assets_dir, count)
                    if poc:
                        pocs.append(poc)
                        finding.poc_ids.append(poc.id)
                        count += 1
                except Exception as exc:
                    log.warning("PoC generation failed for '%s': %s", finding.title, exc)

        log.info("PoC generator: produced %d script(s).", len(pocs))
        return pocs

    def _generate_one(
        self,
        finding: Finding,
        poc_plan: str,
        assets_dir: Path,
        index: int,
    ) -> Poc | None:
        poc_cfg = self._config.poc
        git_instr = (
            "You may also suggest cloning an official exploit PoC from a public git repository "
            "(provide the git clone command in the script)."
            if poc_cfg.allow_git_clone else ""
        )

        client = self._get_client()
        system = self._config.prompts.get("poc_system")
        user = self._config.prompts.get("poc_user").format(
            title=finding.title,
            severity=finding.severity.value,
            description=finding.description[:600],
            cwe=", ".join(finding.cwe) or "unknown",
            exploitability=finding.exploitability or "unknown",
            poc_plan=poc_plan or "No specific plan — use best judgment.",
            target=finding.target,
            git_clone_instruction=git_instr,
        )

        data = client.complete_json(system, user)

        lang = data.get("language", "bash").lower()
        if lang not in ("python", "bash"):
            lang = "bash"
        if lang not in poc_cfg.languages:
            lang = poc_cfg.languages[0] if poc_cfg.languages else "bash"

        script = data.get("script", "")
        if not script.strip():
            return None

        # Prepend shebang if missing
        shebang = _SHEBANGS.get(lang, "")
        if shebang and not script.startswith("#!"):
            script = shebang + "\n\n" + script

        # Denylist safety check
        safe_to_run = data.get("safe_to_run", True)
        safety_notes = data.get("safety_notes", "")
        denylist_safe, denylist_reason = _is_safe(script)
        if not denylist_safe:
            safe_to_run = False
            safety_notes = (safety_notes + f" [Denylist: {denylist_reason}]").strip()

        poc_id = f"poc-{index+1:03d}"
        ext = _EXTENSIONS.get(lang, ".sh")
        filename = f"{poc_id}{ext}"
        script_path = assets_dir / filename

        header = (
            f"# {poc_id}: {finding.title}\n"
            f"# Target: {finding.target}\n"
            f"# CWE: {', '.join(finding.cwe) or 'unknown'}\n"
            f"# Tool: {finding.tool}\n"
            f"# Description: {data.get('description', '')}\n"
            f"# Expected indicator: {data.get('expected_indicator', '')}\n"
            f"# Safe to run: {safe_to_run}\n"
            f"# How to run: {'python3' if lang == 'python' else 'bash'} {filename}\n\n"
        )

        full_script = header + script
        script_path.write_text(full_script, encoding="utf-8")
        if lang == "bash":
            script_path.chmod(0o755)

        log.debug("PoC written: %s", script_path)

        return Poc(
            id=poc_id,
            finding_keys=[self._finding_key(finding)],
            language=lang,
            script=full_script,
            description=data.get("description", ""),
            expected_indicator=data.get("expected_indicator", ""),
            safe_to_run=safe_to_run,
            safety_notes=safety_notes,
            script_path=str(script_path),
            raw_llm=data,
        )

    def _get_category(self, result: "ScanResult") -> str:
        try:
            from vuln_scanner.tools import TOOL_REGISTRY
            cls = TOOL_REGISTRY.get(result.tool)
            if cls:
                return cls().category
        except Exception:
            pass
        return "unknown"
