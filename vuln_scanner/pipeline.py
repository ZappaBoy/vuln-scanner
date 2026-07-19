"""Asset-discovery recon pipeline.

Converts bare domain names into live URL targets through three stages:

  Stage 1 — Subdomain enumeration  (subfinder | amass)
  Stage 2 — DNS resolution          (puredns | dnsx)
  Stage 3 — HTTP liveness probe     (httpx)

Each stage tries tools in configured order; the first binary found on PATH
is used.  Stages whose tool list is empty or whose tools are all missing are
skipped gracefully.

Discovered URLs are scope-validated before being returned.
"""


import logging
import shutil
import subprocess
from typing import TYPE_CHECKING

from vuln_scanner.tools.target import classify_target
from vuln_scanner.tools.enums import TargetType

if TYPE_CHECKING:
    from vuln_scanner.config.models import ReconConfig
    from vuln_scanner.scope import ScopeValidator

log = logging.getLogger(__name__)


def _find_binary(candidates: list[str]) -> str | None:
    for name in candidates:
        if shutil.which(name):
            return name
    return None


def _run(cmd: list[str], timeout: int, label: str) -> list[str]:
    """Run *cmd*, return stdout lines, log failures silently."""
    log.debug("[pipeline:%s] %s", label, " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    except FileNotFoundError:
        log.debug("[pipeline:%s] binary not found: %s", label, cmd[0])
        return []
    except subprocess.TimeoutExpired:
        log.warning("[pipeline:%s] timed out after %ds", label, timeout)
        return []
    except Exception as exc:
        log.warning("[pipeline:%s] error: %s", label, exc)
        return []


# ── Stage 1: subdomain enumeration ───────────────────────────────────────────

def _enumerate_subdomains(domain: str, cfg: "ReconConfig") -> list[str]:
    binary = _find_binary(cfg.enum_tools)
    if not binary:
        log.debug("[pipeline:enum] no enumeration tool available — skipping.")
        return [domain]

    if binary == "subfinder":
        lines = _run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            cfg.timeout, "enum"
        )
    elif binary == "amass":
        lines = _run(
            ["amass", "enum", "-passive", "-d", domain, "-silent"],
            cfg.timeout, "enum"
        )
    else:
        lines = _run([binary, "-d", domain], cfg.timeout, "enum")

    subdomains = [ln for ln in lines if domain in ln]
    log.info("[pipeline:enum] %s → %d subdomain(s) via %s", domain, len(subdomains), binary)
    return subdomains or [domain]


# ── Stage 2: DNS resolution ───────────────────────────────────────────────────

def _resolve_domains(domains: list[str], cfg: "ReconConfig") -> list[str]:
    binary = _find_binary(cfg.resolve_tools)
    if not binary:
        log.debug("[pipeline:resolve] no resolver available — passing through.")
        return domains

    if binary == "dnsx":
        lines = _run(
            ["dnsx", "-silent", "-resp-only"] + [f for d in domains for f in ["-d", d]],
            cfg.timeout, "resolve"
        )
        # dnsx with -resp-only returns resolved IPs; fall back to original hostnames
        # when output is empty
        resolved = lines or domains
    elif binary == "puredns":
        import tempfile
        import os
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="vs_pipeline_")
        try:
            os.write(fd, "\n".join(domains).encode())
            os.close(fd)
            lines = _run(
                ["puredns", "resolve", tmp, "--quiet"],
                cfg.timeout, "resolve"
            )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        resolved = [ln.split()[0] for ln in lines if ln] or domains
    else:
        resolved = domains

    log.info("[pipeline:resolve] %d → %d live host(s) via %s",
             len(domains), len(resolved), binary)
    return resolved


# ── Stage 3: HTTP liveness probe ──────────────────────────────────────────────

def _probe_http(hosts: list[str], cfg: "ReconConfig") -> list[str]:
    binary = _find_binary(cfg.probe_tools)
    if not binary:
        log.debug("[pipeline:probe] no HTTP probe available — using https:// prefix.")
        return [f"https://{h}" if not h.startswith("http") else h for h in hosts]

    if binary == "httpx":
        lines = _run(
            ["httpx", "-silent", "-l", "/dev/stdin", "-o", "/dev/stdout",
             "-follow-redirects", "-status-code"],
            cfg.timeout, "probe",
        )
        # httpx with -l /dev/stdin doesn't work well; pipe via echo
        import tempfile
        import os
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="vs_probe_")
        try:
            os.write(fd, "\n".join(hosts).encode())
            os.close(fd)
            lines = _run(
                ["httpx", "-silent", "-l", tmp, "-follow-redirects"],
                cfg.timeout, "probe"
            )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        urls = [ln.split()[0] for ln in lines if ln.startswith("http")]
    elif binary == "httprobe":
        import tempfile
        import os
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="vs_probe_")
        try:
            os.write(fd, "\n".join(hosts).encode())
            os.close(fd)
            # httprobe reads from stdin
            proc = subprocess.run(
                ["httprobe"], input="\n".join(hosts),
                capture_output=True, text=True, timeout=cfg.timeout
            )
            urls = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        except Exception:
            urls = []
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    else:
        urls = [f"https://{h}" if not h.startswith("http") else h for h in hosts]

    log.info("[pipeline:probe] %d → %d live URL(s) via %s",
             len(hosts), len(urls), binary)
    return urls


# ── Public API ────────────────────────────────────────────────────────────────

class ReconPipeline:
    """Runs asset discovery for HOST-type targets and returns new URL targets."""

    def __init__(self, cfg: "ReconConfig", scope: "ScopeValidator") -> None:
        self._cfg = cfg
        self._scope = scope

    def discover(self, targets: list[str]) -> list[str]:
        """Return newly discovered URL targets from domain-type inputs.

        Targets that are already URLs / IPs / paths are passed through
        unchanged (they don't need recon).  HOST-type targets trigger
        the full enum → resolve → probe pipeline.
        """
        if not self._cfg.enabled:
            return []

        host_targets = [
            t for t in targets
            if TargetType.HOST in classify_target(t)
        ]
        if not host_targets:
            return []

        log.info("[pipeline] Starting recon for %d domain(s): %s",
                 len(host_targets), ", ".join(host_targets))

        discovered: list[str] = []
        for domain in host_targets:
            subdomains = _enumerate_subdomains(domain, self._cfg)
            resolved = _resolve_domains(subdomains, self._cfg)
            urls = _probe_http(resolved, self._cfg)
            discovered.extend(urls)

        # Deduplicate
        seen: set[str] = set()
        unique = [u for u in discovered if u not in seen and not seen.add(u)]  # type: ignore[func-returns-value]

        # Scope-validate discovered assets
        if self._cfg.scope_validate:
            unique = self._scope.filter(unique, discovered=True)

        # Drop any that were already in the original targets list
        existing = set(targets)
        new_targets = [u for u in unique if u not in existing]

        log.info("[pipeline] Recon complete: %d new target(s) discovered.", len(new_targets))
        return new_targets
