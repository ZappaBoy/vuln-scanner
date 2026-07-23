from __future__ import annotations

import asyncio
import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from vuln_scanner.assets import Asset, AssetStore, AssetType
from vuln_scanner.config.models import AppConfig
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus
from vuln_scanner.tools.models import ScanInput, ScanResult

log = logging.getLogger(__name__)

# Passive-mode asset types: only these propagate in PASSIVE / PARANOID mode.
# Active probing, brute-force, and injection tools are suppressed.
_PASSIVE_ASSET_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.SUBDOMAIN,
        AssetType.IP,
        AssetType.URL,
        AssetType.EMAIL,
        AssetType.TECH,
        AssetType.VHOST,
    }
)

# Module-level reference to the active progress tracker so the logging handler
# can clear/redraw the bar line around each log record.
_active_tracker = None  # set to _ProgressTracker instance when TTY scan is running


class _ProgressTracker:
    """Thread-safe progress counter; renders inline in TTY, logs otherwise."""

    def __init__(self, total: int) -> None:
        global _active_tracker
        self._total = total
        self._done = 0
        self._ok = 0
        self._fail = 0
        self._skip = 0
        self._running: set[str] = set()
        self._lock = threading.Lock()
        self._tty = sys.stderr.isatty()
        if self._tty:
            _active_tracker = self

    def deactivate(self) -> None:
        global _active_tracker
        if _active_tracker is self:
            _active_tracker = None

    def add_total(self, n: int) -> None:
        with self._lock:
            self._total += n

    def start(self, label: str) -> None:
        with self._lock:
            self._running.add(label)

    def finish(self, label: str, status: ScanStatus) -> None:
        with self._lock:
            self._running.discard(label)
            self._done += 1
            if status == ScanStatus.SUCCESS:
                self._ok += 1
            elif status == ScanStatus.SKIPPED:
                self._skip += 1
            else:
                self._fail += 1
            if self._tty:
                self._render_tty()

    def _render_tty(self) -> None:
        # Called with _lock held (from finish) or from ProgressAwareHandler (also with _lock held).
        width = 24
        filled = int(width * self._done / max(self._total, 1))
        bar = "█" * filled + "░" * (width - filled)
        # Show tool name only (strip the "→target" suffix) to keep the bar short.
        tool_names = sorted(label.split("→")[0] for label in self._running)
        display = ", ".join(tool_names[:5])
        if len(tool_names) > 5:
            display += f" +{len(tool_names) - 5}"
        suffix = f"  [{display}]" if display else ""
        line = f"\r  [{bar}] {self._done}/{self._total}  ✓{self._ok} ✗{self._fail} ~{self._skip}{suffix}"
        print(line, end="", flush=True, file=sys.stderr)
        if self._done == self._total:
            print(file=sys.stderr)
            self.deactivate()

    def summary_line(self) -> str:
        return f"{self._total} task(s) completed: ✓ {self._ok} success  ✗ {self._fail} failed  ~ {self._skip} skipped"


class ProgressAwareHandler(logging.StreamHandler):
    """Logging handler that clears and redraws the TTY progress bar around each record.

    Prevents log lines from being concatenated onto the bar's overwrite line.
    """

    def emit(self, record: logging.LogRecord) -> None:
        tracker = _active_tracker
        if tracker is None or not tracker._tty:
            super().emit(record)
            return
        with tracker._lock:
            # Erase the current bar line, emit the log record, then redraw.
            self.stream.write("\r\033[2K")
            self.stream.flush()
            super().emit(record)
            tracker._render_tty()


class ScanOrchestrator:
    def __init__(self, config: AppConfig, tools: list[AbstractTool], log_dir: Path | None = None) -> None:
        self._config = config
        self._tools = tools
        self._log_dir = log_dir
        if log_dir is not None:
            log_dir.mkdir(parents=True, exist_ok=True)

    def _filter_tools(self) -> list[AbstractTool]:
        cfg_tools = self._config.tools
        cfg_cats = self._config.categories

        result: list[AbstractTool] = []
        for tool in self._tools:
            if cfg_cats.include and tool.category not in cfg_cats.include:
                log.debug("Skipping tool '%s': category '%s' not in include list.", tool.name, tool.category)
                continue
            if tool.category in cfg_cats.exclude:
                log.debug("Skipping tool '%s': category '%s' is excluded.", tool.name, tool.category)
                continue
            if cfg_tools.include and tool.name not in cfg_tools.include:
                log.debug("Skipping tool '%s': not in include list.", tool.name)
                continue
            if tool.name in cfg_tools.exclude:
                log.debug("Skipping tool '%s': explicitly excluded.", tool.name)
                continue
            result.append(tool)

        return result

    def _make_scan_input(self, target: str, all_targets: list[str]) -> ScanInput:
        return ScanInput(
            targets=all_targets,
            timeout=self._config.scan.timeout,
            mode=self._config.scan.mode,
            rate_limit=self._config.scan.rate_limit,
            auth=self._config.auth.for_target(target),
            proxy=self._config.scan.proxy,
        )

    async def _run_task(
        self,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        tool: AbstractTool,
        target: str,
        scan_input: ScanInput,
        tracker: _ProgressTracker,
    ) -> ScanResult:
        label = f"{tool.name}→{target}"
        timeout_override = self._config.tools.timeouts.get(tool.name)
        if timeout_override is not None:
            scan_input = scan_input.model_copy(update={"timeout": timeout_override})
        tracker.start(label)
        try:
            result = await loop.run_in_executor(executor, tool.run, target, scan_input)
        except Exception as exc:
            log.exception("Unexpected error from tool '%s' on target '%s'.", tool.name, target)
            result = ScanResult(
                tool=tool.name,
                target=target,
                status=ScanStatus.FAILED,
                error=str(exc),
            )
        tracker.finish(label, result.status)

        if self._log_dir is not None and result.raw_output:
            safe = result.target.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_")
            log_file = self._log_dir / f"{result.tool}__{safe[:80]}.log"
            try:
                log_file.write_text(result.raw_output, encoding="utf-8")
                result.log_path = str(log_file)
            except OSError as exc:
                log.debug("Could not write tool log for %s: %s", label, exc)

        icon = "✓" if result.status == ScanStatus.SUCCESS else ("-" if result.status == ScanStatus.SKIPPED else "✗")
        findings_note = f"  {len(result.findings)} finding(s)" if result.findings else ""
        log.info("%s %-22s  %s  (%.1fs%s)", icon, tool.name, target, result.duration, findings_note)
        return result

    # ── Flat matrix (default, chaining disabled) ─────────────────────────────

    async def _run_flat(
        self,
        active_tools: list[AbstractTool],
        targets: list[str],
        max_workers: int,
    ) -> list[ScanResult]:
        scan_inputs = {t: self._make_scan_input(t, targets) for t in targets}

        tasks: list[tuple[AbstractTool, str]] = []
        skipped_count = 0
        for tool in active_tools:
            for target in targets:
                if tool.applies_to(target):
                    tasks.append((tool, target))
                else:
                    skipped_count += 1
                    log.debug("Skipping '%s' for '%s': type not applicable.", tool.name, target)

        log.info(
            "Starting flat scan: %d tool(s) × %d target(s) = %d task(s) (%d type-gated skips) | mode=%s | workers=%d",
            len(active_tools),
            len(targets),
            len(tasks),
            skipped_count,
            self._config.scan.mode.value,
            max_workers,
        )

        tracker = _ProgressTracker(len(tasks))
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            coroutines = [
                self._run_task(loop, executor, tool, target, scan_inputs[target], tracker) for tool, target in tasks
            ]
            results = list(await asyncio.gather(*coroutines))

        log.info(tracker.summary_line())
        return results

    # ── Wave / fixpoint scheduler (chaining enabled) ─────────────────────────

    async def _run_chained(
        self,
        active_tools: list[AbstractTool],
        targets: list[str],
        max_workers: int,
    ) -> list[ScanResult]:
        chaining_cfg = self._config.chaining
        scope_cfg = ScopeValidator.from_config(self._config.scope)
        mode = self._config.scan.mode
        budgets: dict[str, int] = chaining_cfg.asset_budgets

        store = AssetStore()
        store.seed_from_targets(targets)

        # Wave 0: tools with no consumes (operate directly on CLI targets)
        wave0_tools = [t for t in active_tools if not t.consumes]
        chained_tools = [t for t in active_tools if t.consumes]

        log.info(
            "Starting chained scan: %d Wave-0 tool(s), %d chained tool(s) | max_depth=%d | workers=%d",
            len(wave0_tools),
            len(chained_tools),
            chaining_cfg.max_depth,
            max_workers,
        )

        all_results: list[ScanResult] = []
        # (tool.name, target) pairs already executed — prevents re-running
        done_set: set[tuple[str, str]] = set()
        new_targets_added = 0

        loop = asyncio.get_event_loop()
        tracker = _ProgressTracker(0)

        # Shared executor across all waves
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # ── Wave 0 ────────────────────────────────────────────────────────
            wave0_pairs = [
                (tool, t)
                for tool in wave0_tools
                for t in targets
                if tool.applies_to(t) and (tool.name, t) not in done_set
            ]
            tracker.add_total(len(wave0_pairs))
            log.info("Wave 0: %d tasks.", len(wave0_pairs))

            scan_inputs: dict[str, ScanInput] = {t: self._make_scan_input(t, targets) for t in targets}
            if wave0_pairs:
                w0_results = list(
                    await asyncio.gather(
                        *[self._run_task(loop, executor, tool, t, scan_inputs[t], tracker) for tool, t in wave0_pairs]
                    )
                )
                all_results.extend(w0_results)
                for (tool, t), r in zip(wave0_pairs, w0_results):
                    done_set.add((tool.name, t))
                    for asset in tool.extract_assets(r):
                        self._maybe_add_asset(asset, store, scope_cfg, mode, budgets)

            # ── Subsequent waves ─────────────────────────────────────────────
            for wave_num in range(1, chaining_cfg.max_depth + 1):
                if new_targets_added >= chaining_cfg.max_new_targets:
                    log.info("Chaining: max_new_targets=%d reached, stopping.", chaining_cfg.max_new_targets)
                    break

                next_wave: list[tuple[AbstractTool, str, Asset]] = []
                for tool in chained_tools:
                    for consumed_type in tool.consumes:
                        for asset in store.get(consumed_type):
                            target_val = asset.value
                            if (tool.name, target_val) in done_set:
                                continue
                            if not tool.applies_to(target_val):
                                continue
                            next_wave.append((tool, target_val, asset))

                if not next_wave:
                    log.info("Wave %d: fixpoint reached (no new tasks).", wave_num)
                    break

                # Deduplicate (tool, target) pairs (multiple asset types may trigger same pair)
                seen_wave: set[tuple[str, str]] = set()
                deduped: list[tuple[AbstractTool, str, Asset]] = []
                for tool, t, asset in next_wave:
                    key = (tool.name, t)
                    if key not in seen_wave:
                        seen_wave.add(key)
                        deduped.append((tool, t, asset))

                tracker.add_total(len(deduped))
                log.info("Wave %d: %d task(s).", wave_num, len(deduped))

                # Build ScanInputs for any new targets
                known_targets = list(targets)
                new_in_wave = [t for _, t, _ in deduped if t not in scan_inputs]
                for t in new_in_wave:
                    scan_inputs[t] = self._make_scan_input(t, known_targets)
                    new_targets_added += 1

                wave_results = list(
                    await asyncio.gather(
                        *[self._run_task(loop, executor, tool, t, scan_inputs[t], tracker) for tool, t, _ in deduped]
                    )
                )
                all_results.extend(wave_results)
                for (tool, t, _), r in zip(deduped, wave_results):
                    done_set.add((tool.name, t))
                    for asset in tool.extract_assets(r):
                        self._maybe_add_asset(asset, store, scope_cfg, mode, budgets)

        log.info("%s  [asset store: %d assets]", tracker.summary_line(), store.total)
        return all_results

    @staticmethod
    def _maybe_add_asset(
        asset: Asset,
        store: AssetStore,
        scope_cfg: ScopeValidator,
        mode: ScanMode,
        budgets: dict[str, int],
    ) -> None:
        """Gate and store a newly discovered asset."""
        # Mode-aware gate: passive modes only propagate passive asset types
        if mode in (ScanMode.PASSIVE, ScanMode.PARANOID):
            if asset.type not in _PASSIVE_ASSET_TYPES:
                return

        # Budget gate
        budget = budgets.get(asset.type.value, 9999)
        current = len(store.get(asset.type))
        if current >= budget:
            log.debug(
                "Chaining: budget exhausted for %s (budget=%d), dropping %s.", asset.type.value, budget, asset.value
            )
            return

        # Scope gate: only URL and hostname-like assets are scope-checked,
        # and only when the user has configured include/exclude rules. With no
        # scope rules, discovered assets propagate freely (same as the flat-matrix
        # path where no scope is applied between waves).
        val = asset.value
        if (
            asset.type in (AssetType.URL, AssetType.LIVE_HOST, AssetType.SUBDOMAIN, AssetType.VHOST)
            and scope_cfg.has_rules
        ):
            if not scope_cfg.is_in_scope(val, discovered=True):
                log.debug("Chaining: scope rejected asset: %s (%s)", val, asset.type.value)
                return

        store.add(asset)

    # ── Entry point ───────────────────────────────────────────────────────────

    async def _run_async(self) -> list[ScanResult]:
        active_tools = self._filter_tools()
        targets = self._config.scan.targets

        if not active_tools:
            log.warning("No tools selected after filtering.")
            return []
        if not targets:
            log.warning("No targets specified.")
            return []

        max_workers = max(1, self._config.scan.max_concurrent)

        if self._config.chaining.enabled:
            return await self._run_chained(active_tools, targets, max_workers)
        return await self._run_flat(active_tools, targets, max_workers)

    def run(self) -> list[ScanResult]:
        """Run all tool×target pairs concurrently. Blocking entry point."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(asyncio.run, self._run_async()).result()
            return loop.run_until_complete(self._run_async())
        except RuntimeError:
            return asyncio.run(self._run_async())
