"""Nuclei vulnerability scanner — deep integration with NucleiConfig.

Mode-based template profiles (applied when no explicit tags/severity override):

  PARANOID  → severity: info,low          | passive only | no OOB interaction
  PASSIVE   → severity: info,low,medium   | passive only | no OOB interaction
  ACTIVE    → severity: low,med,high,crit | all templates | OOB enabled
  AGGRESSIVE→ severity: all              | + headless (if configured)

User config in [nuclei] always wins over these defaults.
"""
import json
import logging
import subprocess
from typing import TYPE_CHECKING

from vuln_scanner.tools.enums import ScanMode, TargetType, _parse_severity
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool, _as_url

if TYPE_CHECKING:
    from vuln_scanner.config.models import NucleiConfig

log = logging.getLogger(__name__)

# ── Per-mode severity profiles ────────────────────────────────────────────────
_MODE_SEVERITY: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID:   ["info", "low"],
    ScanMode.PASSIVE:    ["info", "low", "medium"],
    ScanMode.ACTIVE:     ["low", "medium", "high", "critical"],
    ScanMode.AGGRESSIVE: ["info", "low", "medium", "high", "critical"],
}

# Tags applied in each mode when no explicit user tags are set
_MODE_EXTRA_TAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID:   ["dns", "ssl", "headers", "misconfiguration"],
    ScanMode.PASSIVE:    ["dns", "ssl", "headers", "misconfiguration", "exposure", "detection"],
    ScanMode.ACTIVE:     [],
    ScanMode.AGGRESSIVE: [],
}

# Tags always excluded for safety
_ALWAYS_EXCLUDE: list[str] = ["dos", "fuzz"]

# Additional per-mode excludes
_MODE_EXCLUDE_TAGS: dict[ScanMode, list[str]] = {
    ScanMode.PARANOID:   ["rce", "sqli", "xss", "ssti", "xxe", "intrusive"],
    ScanMode.PASSIVE:    ["intrusive"],
    ScanMode.ACTIVE:     [],
    ScanMode.AGGRESSIVE: [],
}

# Module-level config slot — set by main.py before scan starts.
_active_nuclei_cfg: "NucleiConfig | None" = None


def configure(cfg: "NucleiConfig") -> None:
    """Set the active NucleiConfig for all subsequent NucleiTool.run() calls."""
    global _active_nuclei_cfg
    _active_nuclei_cfg = cfg


def _nuclei_available() -> bool:
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def update_templates(nuclei_cfg: "NucleiConfig | None" = None) -> None:
    """Run `nuclei -update-templates` to refresh the local template store."""
    if not _nuclei_available():
        log.warning("nuclei binary not found — skipping template update.")
        return

    cmd = ["nuclei", "-update-templates", "-silent"]
    if nuclei_cfg and nuclei_cfg.templates_dir:
        cmd += ["-ud", str(nuclei_cfg.templates_dir)]

    log.info("Updating nuclei templates: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            log.info("Nuclei templates updated successfully.")
        else:
            log.warning("Template update exited %d: %s", result.returncode, result.stderr[:200])
    except subprocess.TimeoutExpired:
        log.warning("Template update timed out after 300s.")
    except Exception as exc:
        log.warning("Template update failed: %s", exc)


class NucleiTool(AbstractTool):
    name: str = "nuclei"
    binary: str = "nuclei"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({
        TargetType.URL, TargetType.HOST, TargetType.IP
    })
    silent_flags: list[str] = ["-silent"]
    verbose_flags: list[str] = ["-v"]

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return _build_nuclei_command(target, scan_input, _active_nuclei_cfg)

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            severity = _parse_severity(info.get("severity", "info"))
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            cve = [r for r in refs if "CVE-" in r.upper()]

            req = item.get("request", "")
            resp = item.get("response", "")[:2000] if item.get("response") else ""

            findings.append(Finding(
                title=info.get("name", item.get("template-id", "Unknown")),
                severity=severity,
                description=(
                    info.get("description", "")
                    or f"Matched at {item.get('matched-at', target)}"
                ),
                tool=self.name,
                target=item.get("host", target),
                cve=cve,
                references=refs,
                request=req,
                response=resp,
                raw=item,
            ))
        return findings


# ── Command builder (also used by tests) ─────────────────────────────────────

def _build_nuclei_command(
    target: str,
    scan_input: ScanInput,
    nuclei_cfg: "NucleiConfig | None",
) -> list[str]:
    """Build the full nuclei argv list from scan_input + NucleiConfig."""
    from vuln_scanner.config.models import NucleiConfig

    cfg = nuclei_cfg or NucleiConfig()
    mode = scan_input.mode

    cmd = ["nuclei", "-u", _as_url(target), "-json"]

    # ── Template directories ───────────────────────────────────────────────
    if cfg.templates_dir:
        cmd += ["-t", str(cfg.templates_dir)]
    for ct in cfg.custom_templates:
        cmd += ["-t", str(ct)]

    # ── Severity filtering ─────────────────────────────────────────────────
    severities = _MODE_SEVERITY[mode]
    cmd += ["-severity", ",".join(severities)]

    # ── Tag filtering ──────────────────────────────────────────────────────
    # User tags replace mode defaults; mode extra-tags only when no user tags.
    include_tags = cfg.tags or _MODE_EXTRA_TAGS[mode]
    if include_tags:
        cmd += ["-tags", ",".join(include_tags)]

    # Exclude: always-safe base + mode-specific + user config (deduplicated)
    exclude_set: list[str] = list(_ALWAYS_EXCLUDE)
    for tag in _MODE_EXCLUDE_TAGS[mode]:
        if tag not in exclude_set:
            exclude_set.append(tag)
    for tag in cfg.exclude_tags:
        if tag not in exclude_set:
            exclude_set.append(tag)
    if exclude_set:
        cmd += ["-etags", ",".join(exclude_set)]

    # ── Workflows ──────────────────────────────────────────────────────────
    for wf in cfg.workflows:
        cmd += ["-w", str(wf)]

    # ── Passive mode ───────────────────────────────────────────────────────
    if mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
        cmd += ["-passive"]

    # ── New-templates-only ─────────────────────────────────────────────────
    if cfg.only_new_templates:
        cmd += ["-new-templates"]

    # ── Performance ────────────────────────────────────────────────────────
    cmd += [
        "-rl",  str(cfg.rate_limit),
        "-bs",  str(cfg.bulk_size),
        "-c",   str(cfg.concurrency),
        "-retries", str(cfg.retries),
    ]

    # ScanInput rate_limit overrides NucleiConfig.rate_limit
    if scan_input.rate_limit is not None:
        rl_idx = cmd.index("-rl")
        cmd[rl_idx + 1] = str(scan_input.rate_limit)

    # Per-request timeout (capped so it doesn't exceed scan timeout)
    cmd += ["-timeout", str(max(5, scan_input.timeout // 10))]

    # ── Headless ───────────────────────────────────────────────────────────
    if cfg.headless and mode == ScanMode.AGGRESSIVE:
        cmd += ["-headless", "-headless-timeout", str(cfg.headless_timeout)]

    # ── Interactsh ─────────────────────────────────────────────────────────
    # Force-disable in safe modes regardless of config
    no_interactsh = cfg.no_interactsh or mode in (ScanMode.PARANOID, ScanMode.PASSIVE)
    if no_interactsh:
        cmd += ["-no-interactsh"]
    else:
        if cfg.interactsh_server:
            cmd += ["-iserver", cfg.interactsh_server]
        if cfg.interactsh_token:
            cmd += ["-itoken", cfg.interactsh_token]

    # ── Authentication ─────────────────────────────────────────────────────
    auth = scan_input.auth
    if auth.is_configured:
        for k, v in auth.effective_headers.items():
            cmd += ["-H", f"{k}: {v}"]
        if auth.username and auth.password:
            cmd += ["-auth-type", "basic", "-auth-cred",
                    f"{auth.username}:{auth.password}"]

    # ── Proxy ──────────────────────────────────────────────────────────────
    if scan_input.proxy:
        cmd += ["-proxy", scan_input.proxy]

    # ── Output ─────────────────────────────────────────────────────────────
    cmd += ["-silent"]

    # User extra args always last so they can override anything above
    cmd += scan_input.extra_args

    return cmd

